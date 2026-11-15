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
	"slices"
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
	_, err := c.Ensure(ctx, "tenant-a", "tenant-a", 2083, Ref{})
	check("port out of range", err)
	_, err = c.Ensure(ctx, "tenant-a", "../etc", 20830, Ref{})
	check("bad slug", err)
	_, err = c.Ensure(ctx, "Tenant", "tenant-a", 20830, Ref{})
	check("bad id", err)
	_, err = c.Validate(ctx, "tenant-a", "../../../etc", "")
	check("bad gen", err)
	_, err = c.Logs(ctx, "tenant-a", 100000)
	check("too many lines", err)
	err = c.call(ctx, http.MethodPost, tenantPath("tenant-a", "signal"), SignalRequest{Signal: "KILL"}, nil)
	check("signal other than HUP", err)
	// 知らない項目（マウントや権限の指定）は断る。
	err = c.call(ctx, http.MethodPost, tenantPath("tenant-a", "ensure"), map[string]any{"slug": "tenant-a", "port": 20830, "mounts": "/"}, nil)
	check("unknown member", err)
	// イメージは ID の形のものだけ、ひな形の版はコードが作れるものだけを受ける（Docker に触れる前に 409。§24.14 の U6-5）。
	conflict := func(name string, err error, target error) {
		t.Helper()
		if e, ok := errors.AsType[*Error](err); !ok || e.Status != http.StatusConflict || !errors.Is(err, target) {
			t.Errorf("%s: %v, want 409 %v", name, err, target)
		}
	}
	_, err = c.Ensure(ctx, "tenant-a", "tenant-a", 20830, Ref{Template: 1, Image: "evil/image:latest"})
	conflict("image by name", err, ErrImageNotAllowed)
	_, err = c.Ensure(ctx, "tenant-a", "tenant-a", 20830, Ref{Template: 99})
	conflict("unknown template", err, ErrUnknownTemplate)
	_, err = c.Validate(ctx, "tenant-a", "0123456789abcdef", "busybox")
	conflict("validate with an image by name", err, ErrImageNotAllowed)
}

// testImage は試験のイメージの ID（Docker に触れない試験で使う）。
const testImage = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// spec1 は版 1 のひな形を作る（作れなければ試験を止める）。
func spec1(t *testing.T, publishAddr, fluentd string, port int, image string) spec {
	t.Helper()
	s, err := tenantSpec("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", publishAddr, fluentd, "12", "tenant-a", port, Ref{Template: 1, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSpec(t *testing.T) {
	s := spec1(t, "", "", 20831, testImage)
	hc := s.HostConfig
	if s.Image != testImage || s.User != "10083:10083" || !hc.Init || !hc.ReadonlyRootfs || hc.Privileged ||
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
	if s.Labels[LabelTenant] != "12" || s.Labels[LabelSlug] != "tenant-a" || s.Labels[LabelPort] != "20831" || s.Labels[LabelTemplate] != "1" || s.Labels[LabelSpec] == "" {
		t.Errorf("labels: %v", s.Labels)
	}
	if other := spec1(t, "", "", 20832, testImage); other.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Error("spec hash does not change with the port")
	}
	// イメージの ID もひな形のハッシュに入る（同じタグで作り直したイメージは別のひな形。§24.14 の U6-1）。
	if other := spec1(t, "", "", 20831, strings.Replace(testImage, "0123", "4567", 1)); other.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Error("spec hash does not change with the image")
	}
	if _, err := tenantSpec("/t", "n", "", "", "12", "tenant-a", 20831, Ref{Template: 2, Image: testImage}); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("unknown template: %v", err)
	}
	// malloc の領域の数を絞る（§24.13 の T5-21）。環境変数もひな形のハッシュに入る（変われば作り直す）。
	if !slices.Equal(s.Env, []string{"MALLOC_ARENA_MAX=2"}) {
		t.Errorf("env: %v", s.Env)
	}
	noEnv := s
	noEnv.Env = nil
	if specHash(noEnv) == s.Labels[LabelSpec] {
		t.Error("spec hash does not change with the environment")
	}
	// 公開するアドレスを指定すると、そのアドレスだけに公開し、ひな形も変わる（作り直す）。
	bound := spec1(t, "192.0.2.1", "", 20831, testImage)
	if b := bound.HostConfig.PortBindings[ContainerPort]; b[0].HostIP != "192.0.2.1" || bound.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Errorf("publish address: %+v", bound.HostConfig.PortBindings)
	}
	// Fluent Bit のアドレスを与えると、fluentd のドライバーで送り、待ち行列を絞る（§24.11 の EA14）。ひな形も変わる（作り直す）。
	fb := spec1(t, "", "localhost:24224", 20831, testImage)
	lc := fb.HostConfig.LogConfig
	if lc.Type != "fluentd" || lc.Config["fluentd-address"] != "localhost:24224" || lc.Config["fluentd-buffer-limit"] != "8192" || lc.Config["tag"] != "tenant.12" ||
		lc.Config["cache-max-size"] != "10m" || fb.Labels[LabelSpec] == s.Labels[LabelSpec] {
		t.Errorf("fluentd: %+v", lc)
	}
	v := validateSpec("/t", "n", "tenant-a", "0123456789abcdef", testImage)
	if v.HostConfig.LogConfig.Type != "json-file" || v.Image != testImage {
		t.Errorf("validate log: %+v", v.HostConfig.LogConfig)
	}
	if v.HostConfig.Mounts[0].Source != "/t/tenant-a/gen/0123456789abcdef" || v.HostConfig.Mounts[0].Target != "/conf/current" {
		t.Errorf("validate mount: %+v", v.HostConfig.Mounts)
	}
}

// 段階 6 より前の作りのハッシュ（b482617 のコードで計算した値）と同じ値を作る。動いているコンテナを版 1 とみなして作り直さないため（§24.14 の U6-5）。
func TestLegacySpecHash(t *testing.T) {
	if h := legacySpecHash("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "203.0.113.5", "127.0.0.1:24224", "17", "acme", 20017); h != "4801bd80dd0331d8" {
		t.Errorf("legacy hash with Fluent Bit = %s", h)
	}
	if h := legacySpecHash("/var/lib/radsec-edge/tenants", "radsec-edge-tenants", "", "", "17", "acme", 20017); h != "11f4aebe498e321e" {
		t.Errorf("legacy hash = %s", h)
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
	if res, err := c.Validate(ctx, slug, gen, ""); err != nil || !res.OK {
		t.Fatalf("Validate = %+v, %v", res, err)
	}

	if r, err := c.Ensure(ctx, slug, slug, port, Ref{}); err != nil || r.Action != EnsureCreated || r.Ref != st.Latest() {
		t.Fatalf("Ensure = %+v, %v (latest %+v)", r, err, st.Latest())
	}
	if r, err := c.Ensure(ctx, slug, slug, port, st.Latest()); err != nil || r.Action != EnsureNone {
		t.Fatalf("second Ensure = %+v, %v", r, err)
	}
	waitRunning(t, c, slug)
	ct := container(t, c, slug)
	if ct.Name != ContainerName(slug) || ct.Port != port || ct.Ref() != st.Latest() {
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
	if r, err := c.Ensure(ctx, slug, slug, port, Ref{}); err != nil || r.Action != EnsureStarted {
		t.Fatalf("Ensure after Stop = %+v, %v", r, err)
	}
	// ポートが変われば作り直す。
	if r, err := c.Ensure(ctx, slug, slug, port+1, Ref{}); err != nil || r.Action != EnsureRecreated {
		t.Fatalf("Ensure with another port = %+v, %v", r, err)
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
	res, err := c.Validate(t.Context(), "t-broken", gen, "")
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

// buildImage は、radsecproxy のイメージにラベルを足しただけの別のイメージ（ID が違う）を作り、tag を付けて ID を返す。後で消す。
func buildImage(t *testing.T, tag string) string {
	t.Helper()
	var rnd [4]byte
	rand.Read(rnd[:])
	cmd := exec.Command("docker", "build", "-q", "-t", tag, "-")
	cmd.Stdin = strings.NewReader("FROM " + Image + "\nLABEL radsec-edge.test=" + hex.EncodeToString(rnd[:]) + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker build %s: %v", tag, err)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		tags, _ := exec.Command("docker", "image", "inspect", "-f", `{{join .RepoTags " "}}`, id).Output()
		for tg := range strings.FieldsSeq(string(tags)) {
			exec.Command("docker", "rmi", tg).Run()
		}
		exec.Command("docker", "rmi", id).Run()
	})
	return id
}

// ひな形のイメージを替えて作り直し、前のイメージに戻せる。テナントのコンテナが使っているイメージのタグがなくなっても（同じタグで別の
// イメージを読み込んだとき）、残すタグを付けて戻せるようにする。radsecproxy のリポジトリでないイメージは使わない（§24.14 の U6-1・U6-5）。
func TestDockerTemplates(t *testing.T) {
	d, tenantsDir, network := dockerEnv(t)
	c := startServer(t, d, tenantsDir, network)
	ctx := t.Context()
	var rnd [3]byte
	rand.Read(rnd[:])
	sfx := hex.EncodeToString(rnd[:])
	slug := "t-" + sfx
	const port = 20996
	st, err := c.Status(ctx)
	if err != nil || !st.ImagePresent || st.LatestTemplate != LatestTemplate {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	newer := buildImage(t, ImageRepo+":test-"+sfx)
	other := buildImage(t, "radsec-edge-test/other:"+sfx)

	f := newFixture(t, tenantsDir, slug)
	gen := f.stage(t)
	if res, err := c.Validate(ctx, slug, gen, newer); err != nil || !res.OK {
		t.Fatalf("Validate with the newer image = %+v, %v", res, err)
	}
	if _, err := c.Validate(ctx, slug, gen, other); !errors.Is(err, ErrImageNotAllowed) {
		t.Errorf("Validate with another repository = %v", err)
	}
	if r, err := c.Ensure(ctx, slug, slug, port, Ref{}); err != nil || r.Action != EnsureCreated {
		t.Fatalf("Ensure = %+v, %v", r, err)
	}
	if _, err := c.Ensure(ctx, slug, slug, port, Ref{Template: 1, Image: other}); !errors.Is(err, ErrImageNotAllowed) {
		t.Errorf("Ensure with another repository = %v", err)
	}
	// 新しいイメージへ作り直す。
	if r, err := c.Ensure(ctx, slug, slug, port, Ref{Template: 1, Image: newer}); err != nil || r.Action != EnsureRecreated || r.Ref.Image != newer {
		t.Fatalf("Ensure with the newer image = %+v, %v", r, err)
	}
	waitRunning(t, c, slug)
	if ct := container(t, c, slug); ct.Ref() != (Ref{Template: 1, Image: newer}) {
		t.Errorf("container after the upgrade = %+v", ct)
	}
	// 新しいイメージのタグを外しても（同じタグで別のイメージを読み込んだのと同じ）、使っているので残すタグが付き、戻せる。
	if out, err := exec.Command("docker", "rmi", "-f", ImageRepo+":test-"+sfx).CombinedOutput(); err != nil {
		t.Fatalf("untag: %v\n%s", err, out)
	}
	st, err = c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keep := ImageRepo + ":" + KeepTagPrefix + ShortImage(newer)
	if !slices.ContainsFunc(st.Images, func(im ImageInfo) bool { return im.ID == newer && slices.Contains(im.Tags, keep) && im.InUse == 1 }) {
		t.Errorf("the image in use is not kept: %+v", st.Images)
	}
	// 前のイメージ（今のタグ）に戻し、また新しいイメージ（残すタグ）にする。
	if r, err := c.Ensure(ctx, slug, slug, port, st.Latest()); err != nil || r.Action != EnsureRecreated || r.Ref != st.Latest() {
		t.Fatalf("Ensure back to the previous image = %+v, %v", r, err)
	}
	if r, err := c.Ensure(ctx, slug, slug, port, Ref{Template: 1, Image: newer}); err != nil || r.Action != EnsureRecreated {
		t.Fatalf("Ensure with the kept image = %+v, %v", r, err)
	}
	waitRunning(t, c, slug)
	if err := c.Remove(ctx, slug); err != nil {
		t.Fatal(err)
	}
}
