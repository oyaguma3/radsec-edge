package edge

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge/edgetest"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// env は試験の環境（DB、ディレクトリ、偽物の agent とヘルスチェック、CA）。
type env struct {
	svc      *Service
	db       *db.DB
	agent    *edgetest.FakeAgent
	probe    *edgetest.FakeProbe
	ca       *pkitest.CA
	serverCA *pkitest.CA
	user     Actor
	// network はテナントのネットワーク（dockerEnv のときだけ）。
	network string
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
	e := &env{db: d, agent: edgetest.NewFakeAgent(), probe: &edgetest.FakeProbe{}, ca: pkitest.NewCA(t, "tenant-a client CA"),
		serverCA: pkitest.NewCA(t, "server CA"), user: Actor{Operator: "op@example.com", Source: db.SourceGUI}}
	e.svc = New(Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: d, Agent: e.agent,
		Store: rsconf.Store{Root: t.TempDir()}, Keys: keystore.Store{Dir: t.TempDir()},
		URNPrefix: "example", DNSDomain: "radsec.test", Secret: "upsecret-123",
		Probe: e.probe.Check, ProbeTimeout: time.Second,
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
