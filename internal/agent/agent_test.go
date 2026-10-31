package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/docker"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// startServer は agent を一時的な unix ソケットで動かし、クライアントを返す。
func startServer(t *testing.T, d *docker.Client, tenantsDir, network string) *Client {
	t.Helper()
	srv := NewServer(ServerOptions{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", Docker: d,
		TenantsDir: tenantsDir, Network: network})
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Routes()}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return NewClient(sock)
}

// 要求の値は Docker に触れる前に断る（ひな形の外の指定を断ること。設計概要 §17）。
func TestRejectsBadRequests(t *testing.T) {
	c := startServer(t, docker.New(filepath.Join(t.TempDir(), "no-docker.sock")), "/tenants", "net")
	ctx := t.Context()
	check := func(name string, err error) {
		t.Helper()
		if e, ok := errors.AsType[*Error](err); !ok || e.Status != http.StatusBadRequest {
			t.Errorf("%s: %v, want 400", name, err)
		}
	}
	_, err := c.Ensure(ctx, "tenant-a", "tenant-a", 2083)
	check("port out of range", err)
	_, err = c.Ensure(ctx, "tenant-a", "../etc", 20830)
	check("bad slug", err)
	_, err = c.Ensure(ctx, "Tenant", "tenant-a", 20830)
	check("bad id", err)
	_, err = c.Validate(ctx, "tenant-a", "../../../etc")
	check("bad gen", err)
	_, err = c.Logs(ctx, "tenant-a", 100000)
	check("too many lines", err)
	err = c.call(ctx, http.MethodPost, tenantPath("tenant-a", "signal"), SignalRequest{Signal: "KILL"}, nil)
	check("signal other than HUP", err)
	// 知らない項目（イメージやマウントの指定）は断る。
	err = c.call(ctx, http.MethodPost, tenantPath("tenant-a", "ensure"), map[string]any{"slug": "tenant-a", "port": 20830, "image": "evil"}, nil)
	check("unknown member", err)
}

func TestSpec(t *testing.T) {
	s := tenantSpec("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "", "", "12", "tenant-a", 20831)
	hc := s.HostConfig
	if s.Image != Image || s.User != "10083:10083" || !hc.Init || !hc.ReadonlyRootfs || hc.Privileged ||
		len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" || hc.SecurityOpt[0] != "no-new-privileges:true" {
		t.Errorf("security options: %+v", s)
	}
	if len(hc.Mounts) != 1 || hc.Mounts[0].Source != "/var/lib/radsec-edge/tenants/tenant-a" || hc.Mounts[0].Target != "/conf" || !hc.Mounts[0].ReadOnly {
		t.Errorf("mounts: %+v", hc.Mounts)
	}
	if b := hc.PortBindings[ContainerPort]; len(b) != 1 || b[0].HostPort != "20831" {
		t.Errorf("ports: %+v", hc.PortBindings)
	}
	if hc.RestartPolicy.Name != "unless-stopped" || hc.LogConfig.Config["max-size"] != "10m" || hc.LogConfig.Config["max-file"] != "5" {
		t.Errorf("restart / log: %+v", hc)
	}
	if s.Labels[LabelTenant] != "12" || s.Labels[LabelSlug] != "tenant-a" || s.Labels[LabelPort] != "20831" || s.Labels[LabelSpec] == "" {
		t.Errorf("labels: %v", s.Labels)
	}
	if other := tenantSpec("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "", "", "12", "tenant-a", 20832); other.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Error("spec hash does not change with the port")
	}
	// 公開するアドレスを指定すると、そのアドレスだけに公開し、ひな形も変わる（作り直す）。
	bound := tenantSpec("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "192.0.2.1", "", "12", "tenant-a", 20831)
	if b := bound.HostConfig.PortBindings[ContainerPort]; b[0].HostIP != "192.0.2.1" || bound.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Errorf("publish address: %+v", bound.HostConfig.PortBindings)
	}
	// Fluent Bit のアドレスを与えると、fluentd のドライバーで送り、待ち行列を絞る（§24.11 の EA14）。ひな形も変わる（作り直す）。
	fb := tenantSpec("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "", "localhost:24224", "12", "tenant-a", 20831)
	lc := fb.HostConfig.LogConfig
	if lc.Type != "fluentd" || lc.Config["fluentd-address"] != "localhost:24224" || lc.Config["fluentd-buffer-limit"] != "8192" || lc.Config["tag"] != "tenant.12" ||
		lc.Config["cache-max-size"] != "10m" || fb.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Errorf("fluentd: %+v", lc)
	}
	v := validateSpec("/t", "n", "tenant-a", "0123456789abcdef")
	if v.HostConfig.LogConfig.Type != "json-file" {
		t.Errorf("validate log: %+v", v.HostConfig.LogConfig)
	}
	if v.HostConfig.Mounts[0].Source != "/t/tenant-a/gen/0123456789abcdef" || v.HostConfig.Mounts[0].Target != "/conf/current" {
		t.Errorf("validate mount: %+v", v.HostConfig.Mounts)
	}
}

// fixture は、試験用のテナントの版を tenantsDir に作る（CA、CRL、サーバー証明書）。
type fixture struct {
	ca    *pkitest.CA
	store rsconf.Store
	in    rsconf.Input
}

func newFixture(t *testing.T, tenantsDir, slug string) *fixture {
	t.Helper()
	ca := pkitest.NewCA(t, slug+" client CA")
	serverCA := pkitest.NewCA(t, "server CA")
	key, _ := pki.NewKey()
	csr, _ := pki.NewCSR(key, "x")
	_, cert := serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames(slug, "radsec.test"), Server: true}, csr)
	return &fixture{ca: ca, store: rsconf.Store{Root: tenantsDir}, in: rsconf.Input{Slug: slug, TenantID: slug, Stamp: rsconf.Stamp{VendorID: 32473, VendorType: 1}, URNPrefix: "example", APs: []string{"ap-001"},
		// 届かない上流でよい（radsecproxy は起動のときに上流に届かなくても終了しない）。
		Auth: netip.MustParseAddrPort("192.0.2.10:1812"), Acct: netip.MustParseAddrPort("192.0.2.10:1813"),
		Secret: "upsecret-123", ClientCAPEM: ca.PEM, CRLPEM: ca.CRL(t, pkitest.CRL{Number: 1}),
		ServerCertPEM: cert, ServerKeyPEM: key, Now: time.Now(),
	}}
}

// stage は版を作って current にし、radsecproxy（10083）が読めるようにする（試験では、ファイルは試験を動かす利用者のもの）。
func (f *fixture) stage(t *testing.T) string {
	t.Helper()
	b, err := rsconf.Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := f.store.Stage(f.in.Slug, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Activate(f.in.Slug, gen); err != nil {
		t.Fatal(err)
	}
	OpenForTest(t, f.store.Root)
	return gen
}

// OpenForTest は、試験のディレクトリをほかの利用者（コンテナの 10083）が読めるようにする。
func OpenForTest(t *testing.T, dir string) {
	t.Helper()
	os.Chmod(dir, 0o755)
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
}

// dockerEnv は、本物の Docker を使う試験の準備（ネットワークと後片付け）をする。EDGE_TEST_DOCKER=1 のときだけ動かす。
func dockerEnv(t *testing.T) (*docker.Client, string, string) {
	t.Helper()
	if os.Getenv("EDGE_TEST_DOCKER") != "1" {
		t.Skip("EDGE_TEST_DOCKER=1 のときだけ動かす")
	}
	d := docker.New("/var/run/docker.sock")
	var rnd [4]byte
	rand.Read(rnd[:])
	network := "radsec-edge-test-" + hex.EncodeToString(rnd[:])
	if out, err := exec.Command("docker", "network", "create", network).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	tenantsDir := t.TempDir()
	t.Cleanup(func() {
		ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "network="+network).Output()
		for id := range strings.FieldsSeq(string(ids)) {
			exec.Command("docker", "rm", "-f", id).Run()
		}
		exec.Command("docker", "network", "rm", network).Run()
	})
	return d, tenantsDir, network
}

func TestDockerLifecycle(t *testing.T) {
	d, tenantsDir, network := dockerEnv(t)
	c := startServer(t, d, tenantsDir, network)
	ctx := t.Context()
	var rnd [3]byte
	rand.Read(rnd[:])
	slug := "t-" + hex.EncodeToString(rnd[:])
	const port = 20997

	st, err := c.Status(ctx)
	if err != nil || !st.DockerOK || !st.ImagePresent || !st.NetworkPresent {
		t.Fatalf("Status = %+v, %v（イメージは images/radsecproxy から作っておく）", st, err)
	}
	if _, err := c.Logs(ctx, slug, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("Logs of a missing container: %v", err)
	}

	f := newFixture(t, tenantsDir, slug)
	gen := f.stage(t)
	if res, err := c.Validate(ctx, slug, gen); err != nil || !res.OK {
		t.Fatalf("Validate = %+v, %v", res, err)
	}

	if a, err := c.Ensure(ctx, slug, slug, port); err != nil || a != EnsureCreated {
		t.Fatalf("Ensure = %q, %v", a, err)
	}
	if a, err := c.Ensure(ctx, slug, slug, port); err != nil || a != EnsureNone {
		t.Fatalf("second Ensure = %q, %v", a, err)
	}
	waitRunning(t, c, slug)
	ct := container(t, c, slug)
	if ct.Name != ContainerName(slug) || ct.Port != port || !ct.SpecCurrent {
		t.Errorf("container = %+v", ct)
	}
	// 公開したポートで TLS を受けている（ハンドシェイクの中身はヘルスチェックの試験で確かめる）。
	conn, err := net.DialTimeout("tcp", "127.0.0.1:20997", 5*time.Second)
	if err != nil {
		t.Fatalf("dial the published port: %v", err)
	}
	conn.Close()

	if err := c.SIGHUP(ctx, slug); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(ctx, slug); err != nil {
		t.Fatal(err)
	}
	waitRunning(t, c, slug)
	logs, err := c.Logs(ctx, slug, 50)
	if err != nil || !strings.Contains(logs, "radsecproxy") {
		t.Errorf("Logs = %q, %v", logs, err)
	}
	if err := c.Stop(ctx, slug); err != nil {
		t.Fatal(err)
	}
	if ct := container(t, c, slug); ct.Running {
		t.Errorf("running after Stop: %+v", ct)
	}
	if a, err := c.Ensure(ctx, slug, slug, port); err != nil || a != EnsureStarted {
		t.Fatalf("Ensure after Stop = %q, %v", a, err)
	}
	// ポートが変われば作り直す。
	if a, err := c.Ensure(ctx, slug, slug, port+1); err != nil || a != EnsureRecreated {
		t.Fatalf("Ensure with another port = %q, %v", a, err)
	}
	waitRunning(t, c, slug)
	if ct := container(t, c, slug); ct.Port != port+1 {
		t.Errorf("port after recreate = %d", ct.Port)
	}
	if err := c.Remove(ctx, slug); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx, slug); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove = %v", err)
	}
}

func TestDockerValidateRejects(t *testing.T) {
	d, tenantsDir, network := dockerEnv(t)
	c := startServer(t, d, tenantsDir, network)
	f := newFixture(t, tenantsDir, "t-broken")
	b, err := rsconf.Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	b[rsconf.FileConf] = []byte(strings.Replace(string(b[rsconf.FileConf]), "CRLCheck on", "CRLCheck maybe", 1))
	gen, err := f.store.Stage("t-broken", b)
	if err != nil {
		t.Fatal(err)
	}
	OpenForTest(t, tenantsDir)
	res, err := c.Validate(t.Context(), "t-broken", gen)
	if err != nil || res.OK || res.Output == "" {
		t.Fatalf("Validate(broken) = %+v, %v", res, err)
	}
	// 捨てるコンテナは残らない。
	if cs, _ := d.List(t.Context(), LabelValidate); len(cs) != 0 {
		t.Errorf("validation containers left: %v", cs)
	}
}

func container(t *testing.T, c *Client, id string) Container {
	t.Helper()
	st, err := c.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ct, ok := st.Container(id)
	if !ok {
		t.Fatalf("no container for %s: %+v", id, st)
	}
	return ct
}

func waitRunning(t *testing.T, c *Client, id string) {
	t.Helper()
	for range 50 {
		if ct := container(t, c, id); ct.Running && !ct.Restarting {
			time.Sleep(300 * time.Millisecond) // radsecproxy が待ち受けを始めるまで
			if ct := container(t, c, id); ct.Running {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := c.Logs(t.Context(), id, 50)
	t.Fatalf("container %s is not running:\n%s", id, logs)
}
