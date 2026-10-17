package db

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *DB {
	t.Helper()
	d, err := Open(t.Context(), filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return d
}

var (
	auth = netip.MustParseAddrPort("10.0.0.10:1812")
	acct = netip.MustParseAddrPort("10.0.0.10:1813")
)

func spec(slug string, port int) TenantSpec {
	return TenantSpec{ID: slug, Slug: slug, Port: port, AuthUpstream: auth, AcctUpstream: acct}
}

func TestMigrate(t *testing.T) {
	d := open(t)
	applied, err := d.Migrate(t.Context())
	if err != nil || len(applied) != 0 {
		t.Fatalf("second Migrate = %v, %v", applied, err)
	}
	v, err := d.SchemaVersion(t.Context())
	if err != nil || v != 1 {
		t.Fatalf("SchemaVersion = %d, %v", v, err)
	}
	// 新しい版で移行した DB は、古い版では使わない。
	if _, err := d.sql.Exec("INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Migrate(t.Context()); err == nil {
		t.Error("Migrate with a newer schema = nil")
	}
}

func TestTenants(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	now := time.UnixMilli(1_700_000_000_000)
	d.SetNow(func() time.Time { return now })

	a, err := d.CreateTenant(ctx, spec("tenant-a", 20830))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Enabled || a.DesiredVersion != 1 || a.AppliedVersion != 0 || !a.Pending() || !a.CreatedAt.Equal(now) {
		t.Errorf("created: %+v", a)
	}
	if a.AuthUpstream != auth || a.AcctUpstream != acct {
		t.Errorf("upstream: %v %v", a.AuthUpstream, a.AcctUpstream)
	}
	// slug・ポートの重なりは断る。
	if _, err := d.CreateTenant(ctx, spec("tenant-a", 20831)); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate slug: %v", err)
	}
	if _, err := d.CreateTenant(ctx, spec("tenant-b", 20830)); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate port: %v", err)
	}
	// 規則に合わない名前とポートは断る。
	for _, s := range []TenantSpec{spec("Bad", 20832), spec("ok", 20000), {ID: "ok", Slug: "ok", Port: 20832}} {
		if _, err := d.CreateTenant(ctx, s); err == nil {
			t.Errorf("CreateTenant(%+v) = nil", s)
		}
	}
	p, err := d.FreePort(ctx, 20830, 20999)
	if err != nil || p != 20831 {
		t.Errorf("FreePort = %d, %v", p, err)
	}

	u, err := d.UpdateTenant(ctx, "tenant-a", func(t *Tenant) error {
		t.ClientCAPEM = "ca"
		t.Enabled = false
		return nil
	})
	if err != nil || u.DesiredVersion != 2 || u.ClientCAPEM != "ca" || u.Enabled {
		t.Errorf("UpdateTenant = %+v, %v", u, err)
	}
	if err := d.MarkApplied(ctx, "tenant-a", 2, "h"); err != nil {
		t.Fatal(err)
	}
	got, err := d.Tenant(ctx, "tenant-a")
	if err != nil || got.Pending() || got.AppliedHash != "h" {
		t.Errorf("after MarkApplied: %+v, %v", got, err)
	}
	if _, err := d.Tenant(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Tenant(none) = %v", err)
	}
	if err := d.DeleteTenant(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTenant(ctx, "tenant-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteTenant = %v", err)
	}
}

func TestAPsAndNASIdentifier(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	if _, err := d.CreateTenant(ctx, spec("a", 20830)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTenant(ctx, spec("a-b", 20831)); err != nil {
		t.Fatal(err)
	}
	ap, err := d.PutAP(ctx, AP{TenantID: "a", Name: "b-c"})
	if err != nil || ap.NASID != "a-b-c" {
		t.Fatalf("PutAP = %+v, %v", ap, err)
	}
	// テナント a-b の AP c は、テナント a の AP b-c と NAS-Identifier（a-b-c）が重なるので断る（設計概要 §8.2）。
	if _, err := d.PutAP(ctx, AP{TenantID: "a-b", Name: "c"}); !errors.Is(err, ErrConflict) {
		t.Errorf("colliding NAS-Identifier: %v", err)
	}
	// テナント a の AP b-probe は、テナント a-b のヘルスチェックの NAS-Identifier（a-b-probe）と重なる。
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "b-probe"}); !errors.Is(err, ErrConflict) {
		t.Errorf("colliding with probe: %v", err)
	}
	// 逆に、既存の AP の NAS-Identifier と重なるヘルスチェックを持つテナントも作れない（a + b-c → テナント a-b-c の a-b-c-probe ではなく、
	// テナント a の AP x-probe があるときのテナント a-x）。
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "x-probe"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTenant(ctx, spec("a-x", 20832)); !errors.Is(err, ErrConflict) {
		t.Errorf("tenant whose probe collides: %v", err)
	}
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "probe"}); err == nil {
		t.Error("reserved AP name accepted")
	}
	// 同じ AP をもう一度入れると、証明書の情報を書き換える。
	na := time.UnixMilli(1_800_000_000_000)
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "b-c", CertSerial: "ab", CertNotAfter: na}); err != nil {
		t.Fatal(err)
	}
	aps, err := d.APs(ctx, "a")
	if err != nil || len(aps) != 2 || aps[0].CertSerial != "ab" || !aps[0].CertNotAfter.Equal(na) {
		t.Fatalf("APs = %+v, %v", aps, err)
	}
	tn, _ := d.Tenant(ctx, "a")
	if tn.DesiredVersion != 4 {
		t.Errorf("DesiredVersion = %d, want 4", tn.DesiredVersion)
	}
	if err := d.DeleteAP(ctx, "a", "b-c"); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAP(ctx, "a", "b-c"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteAP = %v", err)
	}
	counts, _ := d.CountAPs(ctx)
	if counts["a"] != 1 {
		t.Errorf("CountAPs = %v", counts)
	}
	// テナントを消すと AP も消える。
	if err := d.DeleteTenant(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if aps, _ := d.APs(ctx, "a"); len(aps) != 0 {
		t.Errorf("APs after DeleteTenant = %v", aps)
	}
}

func TestCRLAppliesAudit(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	if _, err := d.CreateTenant(ctx, spec("a", 20830)); err != nil {
		t.Fatal(err)
	}
	c, err := d.CRL(ctx, "a")
	if err != nil || c.PEM != "" || c.TenantID != "a" {
		t.Fatalf("empty CRL = %+v, %v", c, err)
	}
	next := time.UnixMilli(1_800_000_000_000)
	c.PEM, c.Number, c.NextUpdate, c.Source = "pem", "12345678901234567890", next, "fetch"
	if err := d.PutCRL(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.ETag = "e"
	if err := d.PutCRL(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := d.CRL(ctx, "a")
	if got.Number != "12345678901234567890" || got.ETag != "e" || !got.NextUpdate.Equal(next) {
		t.Errorf("CRL = %+v", got)
	}

	for i := range 3 {
		if err := d.InsertApply(ctx, Apply{TenantID: "a", Version: int64(i + 1), Trigger: TriggerApply, Result: ResultOK,
			Started: time.Now(), Finished: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	as, err := d.Applies(ctx, "a", 2)
	if err != nil || len(as) != 2 || as[0].Version != 3 {
		t.Errorf("Applies = %+v, %v", as, err)
	}

	if err := d.InsertAudit(ctx, AuditEntry{Operator: "op@example.com", Source: SourceGUI, Action: "tenant.create", Target: "a",
		Detail: map[string]any{"port": 20830}}); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertAudit(ctx, AuditEntry{Source: SourceSystem, Action: "crl.install", Target: "a"}); err != nil {
		t.Fatal(err)
	}
	es, err := d.ListAudit(ctx, 0, 10)
	if err != nil || len(es) != 2 || es[0].Action != "crl.install" || es[1].Detail["port"] != float64(20830) {
		t.Fatalf("ListAudit = %+v, %v", es, err)
	}
	older, _ := d.ListAudit(ctx, es[0].ID, 10)
	if len(older) != 1 {
		t.Errorf("ListAudit(before) = %+v", older)
	}
	if err := d.InsertAudit(ctx, AuditEntry{Source: "bad", Action: "x"}); err == nil {
		t.Error("bad source accepted")
	}
}
