package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// fakeAgent は agent の代わり（コンテナの状態を覚え、呼び出しを記録する）。
type fakeAgent struct {
	mu         sync.Mutex
	containers map[string]*agent.Container
	calls      []string
	// validateOK は Validate の結果、failEnsure は Ensure の誤り。
	validateOK bool
	failEnsure error
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{containers: map[string]*agent.Container{}, validateOK: true}
}

func (f *fakeAgent) call(s string) {
	f.calls = append(f.calls, s)
}

// takeCalls は記録した呼び出しを返して空にする。
func (f *fakeAgent) takeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func (f *fakeAgent) Status(context.Context) (agent.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := agent.Status{DockerOK: true, ImagePresent: true, NetworkPresent: true}
	for _, c := range f.containers {
		st.Containers = append(st.Containers, *c)
	}
	return st, nil
}

func (f *fakeAgent) Ensure(_ context.Context, id, slug string, port int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ensure " + id)
	if f.failEnsure != nil {
		return "", f.failEnsure
	}
	c, ok := f.containers[id]
	switch {
	case !ok:
		f.containers[id] = &agent.Container{TenantID: id, Slug: slug, Name: agent.ContainerName(slug), State: "running", Running: true, Port: port, SpecCurrent: true}
		return agent.EnsureCreated, nil
	case c.Port != port:
		c.Port, c.Running, c.State = port, true, "running"
		return agent.EnsureRecreated, nil
	case !c.Running:
		c.Running, c.State = true, "running"
		return agent.EnsureStarted, nil
	}
	return agent.EnsureNone, nil
}

func (f *fakeAgent) op(name, id string, fn func(c *agent.Container)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(name + " " + id)
	c, ok := f.containers[id]
	if !ok {
		return agent.ErrNotFound
	}
	if fn != nil {
		fn(c)
	}
	return nil
}

func (f *fakeAgent) Restart(_ context.Context, id string) error { return f.op("restart", id, nil) }
func (f *fakeAgent) SIGHUP(_ context.Context, id string) error  { return f.op("sighup", id, nil) }
func (f *fakeAgent) Stop(_ context.Context, id string) error {
	return f.op("stop", id, func(c *agent.Container) { c.Running, c.State = false, "exited" })
}
func (f *fakeAgent) Remove(_ context.Context, id string) error {
	err := f.op("remove", id, nil)
	f.mu.Lock()
	delete(f.containers, id)
	f.mu.Unlock()
	return err
}
func (f *fakeAgent) Logs(context.Context, string, int) (string, error) { return "", nil }
func (f *fakeAgent) Validate(_ context.Context, slug, gen string) (agent.ValidateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("validate " + slug)
	if !f.validateOK {
		return agent.ValidateResult{Output: "syntax error"}, nil
	}
	return agent.ValidateResult{OK: true}, nil
}

// fakeProbe はヘルスチェックの代わり。fail が true の間は失敗する。
type fakeProbe struct {
	mu    sync.Mutex
	fail  bool
	addrs []string
}

func (p *fakeProbe) check(_ context.Context, addr string, _ tls.Certificate, _ *x509.Certificate) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addrs = append(p.addrs, addr)
	if p.fail {
		return errors.New("probe failed")
	}
	return nil
}

func (p *fakeProbe) setFail(v bool) {
	p.mu.Lock()
	p.fail = v
	p.mu.Unlock()
}

// env は試験の環境（DB、ディレクトリ、偽物の agent とヘルスチェック、CA）。
type env struct {
	svc      *Service
	db       *db.DB
	agent    *fakeAgent
	probe    *fakeProbe
	ca       *pkitest.CA
	serverCA *pkitest.CA
	user     Actor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	e := &env{db: d, agent: newFakeAgent(), probe: &fakeProbe{}, ca: pkitest.NewCA(t, "tenant-a client CA"),
		serverCA: pkitest.NewCA(t, "server CA"), user: Actor{Operator: "op@example.com", Source: db.SourceGUI}}
	e.svc = New(Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d, Agent: e.agent,
		Store: rsconf.Store{Root: t.TempDir()}, Keys: keystore.Store{Dir: t.TempDir()},
		URNPrefix: "example", DNSDomain: "radsec.test", Secret: "upsecret-123",
		Probe: e.probe.check, ProbeTimeout: time.Second,
	})
	return e
}

var (
	authUp = netip.MustParseAddrPort("10.0.0.10:1812")
	acctUp = netip.MustParseAddrPort("10.0.0.10:1813")
)

// readyTenant はテナントを作り、CA の証明書・CRL・サーバー証明書・ヘルスチェック用の証明書を取り込む。
func (e *env) readyTenant(t *testing.T, slug string) db.Tenant {
	t.Helper()
	ctx := t.Context()
	s := e.svc
	tn, err := s.CreateTenant(ctx, e.user, TenantInput{Slug: slug, Auth: authUp, Acct: acctUp})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportClientCA(ctx, e.user, slug, e.ca.PEM); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallCRL(ctx, e.user, slug, e.ca.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	csr, err := s.CSR(ctx, e.user, slug, keystore.Server)
	if err != nil {
		t.Fatal(err)
	}
	_, cert := e.serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames(slug, "radsec.test"), Server: true}, csr)
	if err := s.ImportCert(ctx, e.user, slug, keystore.Server, cert); err != nil {
		t.Fatal(err)
	}
	csr, err = s.CSR(ctx, e.user, slug, keystore.Probe)
	if err != nil {
		t.Fatal(err)
	}
	_, cert = e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", slug, "probe")}, csr)
	if err := s.ImportCert(ctx, e.user, slug, keystore.Probe, cert); err != nil {
		t.Fatal(err)
	}
	if tn, err = e.db.Tenant(ctx, slug); err != nil {
		t.Fatal(err)
	}
	return tn
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}
