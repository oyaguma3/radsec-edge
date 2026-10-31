package db

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
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
	if err != nil || v != 3 {
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
	for _, s := range []TenantSpec{spec("Bad", 20832), spec("ok", 19999), {ID: "ok", Slug: "ok", Port: 20832}} {
		if _, err := d.CreateTenant(ctx, s); err == nil {
			t.Errorf("CreateTenant(%+v) = nil", s)
		}
	}
	p, err := d.FreePort(ctx, 20830, 21999)
	if err != nil || p != 20831 {
		t.Errorf("FreePort = %d, %v", p, err)
	}

	u, err := d.UpdateTenant(ctx, "tenant-a", func(t *Tenant) error {
		t.ClientCAPEM = "ca"
		t.Enabled = false // UpdateTenant では変わらない
		return nil
	})
	if err != nil || u.DesiredVersion != 2 || u.ClientCAPEM != "ca" || !u.Enabled {
		t.Errorf("UpdateTenant = %+v, %v", u, err)
	}
	if err := d.SetEnabled(ctx, "tenant-a", false); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkApplied(ctx, "tenant-a", 2, "h", 20830); err != nil {
		t.Fatal(err)
	}
	got, err := d.Tenant(ctx, "tenant-a")
	if err != nil || got.Pending() || got.AppliedHash != "h" || got.AppliedPort != 20830 || got.Enabled || got.DesiredVersion != 2 {
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

func TestSeen(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	if _, err := d.CreateTenant(ctx, spec("a", 20830)); err != nil {
		t.Fatal(err)
	}
	if c, err := d.LogCursor(ctx, "a"); err != nil || !c.IsZero() {
		t.Fatalf("LogCursor = %v, %v", c, err)
	}
	t0 := time.UnixMilli(1_800_000_000_000)
	cursor := time.Date(2027, 1, 15, 8, 0, 0, 123456789, time.UTC)
	err := d.ApplySeen(ctx, "a", []SeenEvent{
		{AP: "ap-1", Kind: SeenUp, At: t0, IP: "192.0.2.1"},
		{AP: "ap-2", Kind: SeenReject, At: t0},
		{AP: "ap-1", Kind: SeenDown, At: t0.Add(time.Minute)},
		{AP: "ap-1", Kind: SeenUp, At: t0.Add(2 * time.Minute), IP: "192.0.2.2"},
	}, cursor, false)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := d.Seen(ctx, "a")
	if a := s["ap-1"]; !a.Connected || a.LastIP != "192.0.2.2" || !a.LastUp.Equal(t0.Add(2*time.Minute)) || !a.LastDown.Equal(t0.Add(time.Minute)) {
		t.Errorf("ap-1 = %+v", a)
	}
	if b := s["ap-2"]; b.Connected || !b.LastReject.Equal(t0) {
		t.Errorf("ap-2 = %+v", b)
	}
	if c, _ := d.LogCursor(ctx, "a"); !c.Equal(cursor) {
		t.Errorf("LogCursor = %v", c)
	}
}

// 共通のブロックの接続は送信元の IP ごとに数え、コンテナを起動し直したら数え直し、テナントごとに上限まで残す。
func TestSharedSeen(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	if _, err := d.CreateTenant(ctx, spec("a", 20830)); err != nil {
		t.Fatal(err)
	}
	t0 := time.UnixMilli(1_800_000_000_000)
	err := d.ApplySeen(ctx, "a", []SeenEvent{
		{Shared: true, Kind: SeenUp, At: t0, IP: "192.0.2.1"},
		{Shared: true, Kind: SeenUp, At: t0.Add(time.Second), IP: "192.0.2.1"},
		{Shared: true, Kind: SeenUp, At: t0.Add(2 * time.Second), IP: "192.0.2.2"},
		{Shared: true, Kind: SeenDown, At: t0.Add(3 * time.Second), IP: "192.0.2.1"},
		{Shared: true, Kind: SeenDown, At: t0.Add(4 * time.Second), IP: "192.0.2.2"},
		{Shared: true, Kind: SeenDown, At: t0.Add(5 * time.Second), IP: "192.0.2.2"}, // 数は 0 より下がらない
	}, t0, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.SharedSeens(ctx, "a")
	if err != nil || len(got) != 2 {
		t.Fatalf("SharedSeens = %+v, %v", got, err)
	}
	if got[0].IP != "192.0.2.2" || got[0].Connections != 0 || got[1].IP != "192.0.2.1" || got[1].Connections != 1 || !got[1].LastDown.Equal(t0.Add(3*time.Second)) {
		t.Errorf("seen = %+v", got)
	}
	// 共通のブロックの出来事は、AP の行に入らない。
	if s, _ := d.Seen(ctx, "a"); len(s) != 0 {
		t.Errorf("ap_seen = %+v", s)
	}
	// コンテナを起動し直した後は数え直す。
	if err := d.ApplySeen(ctx, "a", []SeenEvent{{Shared: true, Kind: SeenUp, At: t0.Add(time.Hour), IP: "192.0.2.2"}}, t0, true); err != nil {
		t.Fatal(err)
	}
	got, _ = d.SharedSeens(ctx, "a")
	if got[0].IP != "192.0.2.2" || got[0].Connections != 1 || got[1].Connections != 0 {
		t.Errorf("after restart = %+v", got)
	}
	// 上限まで残す（新しいものを残す）。
	var ev []SeenEvent
	for i := range keepSharedSeen + 5 {
		ev = append(ev, SeenEvent{Shared: true, Kind: SeenUp, At: t0.Add(time.Duration(i+10) * time.Hour), IP: "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256)})
	}
	if err := d.ApplySeen(ctx, "a", ev, t0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = d.SharedSeens(ctx, "a")
	if len(got) != keepSharedSeen || got[0].IP != ev[len(ev)-1].IP {
		t.Errorf("kept %d, first %s", len(got), got[0].IP)
	}
}

func TestSetTrust(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	tn, err := d.CreateTenant(ctx, spec("a", 20830))
	if err != nil {
		t.Fatal(err)
	}
	cidrs := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	cas := []BroughtCA{{CAID: "brought.a.x", CertPEM: "x", HasCRL: true}, {CAID: "brought.a.y", CertPEM: "y"}}
	if err := d.SetTrust(ctx, "a", cas, cidrs, "CN", "^a$"); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Tenant(ctx, "a")
	if got.DesiredVersion != tn.DesiredVersion+1 || len(got.SourceCIDRs) != 2 || got.SourceCIDRs[1] != cidrs[1] || got.SharedMatchAttr != "CN" || got.SharedMatchPattern != "^a$" {
		t.Errorf("tenant = %+v", got)
	}
	list, _ := d.BroughtCAs(ctx, "a")
	if len(list) != 2 || list[0].CAID != "brought.a.x" || !list[0].HasCRL || list[1].HasCRL {
		t.Errorf("cas = %+v", list)
	}
	for _, id := range []string{"", "brought.a.x", "brought.a.y"} {
		if err := d.PutCRL(ctx, CRL{TenantID: "a", CAID: id, PEM: "p" + id}); err != nil {
			t.Fatal(err)
		}
	}
	// CRL は CA ごとに持つ。一覧から外した CA と、証明書を替えた CA の CRL は消える。発行した CA の CRL は残る。
	if c, _ := d.CRLOf(ctx, "a", "brought.a.x"); c.PEM != "pbrought.a.x" {
		t.Errorf("crl = %+v", c)
	}
	if err := d.SetTrust(ctx, "a", []BroughtCA{{CAID: "brought.a.x", CertPEM: "x2", HasCRL: true}}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"": "p", "brought.a.x": "", "brought.a.y": ""} {
		if c, _ := d.CRLOf(ctx, "a", id); c.PEM != want {
			t.Errorf("crl %q = %q", id, c.PEM)
		}
	}
	got, _ = d.Tenant(ctx, "a")
	if len(got.SourceCIDRs) != 0 {
		t.Errorf("cidrs = %v", got.SourceCIDRs)
	}
	if err := d.SetTrust(ctx, "none", nil, nil, "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("no tenant: %v", err)
	}
	// テナントを消すと一緒に消える。
	if err := d.DeleteTenant(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.BroughtCAs(ctx, "a"); len(list) != 0 {
		t.Errorf("after delete: %+v", list)
	}
}

func TestGroupKind(t *testing.T) {
	d := open(t)
	ctx := t.Context()
	if _, err := d.CreateTenant(ctx, spec("a", 20830)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "ap-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "g-1", Kind: KindGroup, Purpose: "unifi"}); err != nil {
		t.Fatal(err)
	}
	// 種類をまたいで同じ名前は断る。
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "ap-1", Kind: KindGroup, Purpose: "box"}); !errors.Is(err, ErrConflict) {
		t.Errorf("group named like an AP: %v", err)
	}
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "g-1"}); !errors.Is(err, ErrConflict) {
		t.Errorf("AP named like a group: %v", err)
	}
	if _, err := d.PutAP(ctx, AP{TenantID: "a", Name: "g-1", Kind: KindGroup, Purpose: "box"}); err != nil {
		t.Errorf("update group: %v", err)
	}
	aps, _ := d.APs(ctx, "a")
	if len(aps) != 2 || aps[0].Kind != KindAP || aps[1].Kind != KindGroup || aps[1].Purpose != "box" || aps[1].NASID != "a-g-1" {
		t.Errorf("aps = %+v", aps)
	}
}

// 段階 3 までの DB（移行 0002 まで）に行を入れてから 0003 を適用し、行が残り、新しい範囲と外部キーが効くことを確かめる。
func TestMigrate0003KeepsRows(t *testing.T) {
	ctx := t.Context()
	d, err := Open(ctx, filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.sql.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"0001_init.sql", "0002_ap_seen.sql"} {
		b, err := os.ReadFile("migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.sql.ExecContext(ctx, string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	for _, s := range []string{
		`INSERT INTO schema_migrations VALUES (1, 'init', 1), (2, 'ap_seen', 1)`,
		`INSERT INTO tenants (id, slug, port, auth_upstream, acct_upstream, client_ca_pem, desired_version, applied_version, created_at, updated_at)
			VALUES ('t', 't', 20830, '10.0.0.1:1812', '10.0.0.1:1813', 'ca', 3, 2, 1, 1)`,
		`INSERT INTO aps (tenant_id, name, nas_id, cert_serial, created_at, updated_at) VALUES ('t', 'ap-1', 't-ap-1', 'ab', 1, 1)`,
		`INSERT INTO crls (tenant_id, pem, number, source) VALUES ('t', 'crl', '7', 'fetch')`,
		`INSERT INTO ap_seen (tenant_id, ap, connected, last_ip) VALUES ('t', 'ap-1', 1, '192.0.2.1')`,
		`INSERT INTO log_cursors (tenant_id, since) VALUES ('t', '2027-01-15T08:00:00Z')`,
	} {
		if _, err := d.sql.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := d.Migrate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) == 0 || applied[0] != 3 {
		t.Fatalf("applied %v", applied)
	}
	tn, err := d.Tenant(ctx, "t")
	if err != nil || tn.Port != 20830 || tn.ClientCAPEM != "ca" || tn.DesiredVersion != 3 || tn.AppliedVersion != 2 || len(tn.SourceCIDRs) != 0 {
		t.Errorf("tenant = %+v, %v", tn, err)
	}
	aps, _ := d.APs(ctx, "t")
	if len(aps) != 1 || aps[0].Kind != KindAP || aps[0].CertSerial != "ab" {
		t.Errorf("aps = %+v", aps)
	}
	if c, _ := d.CRL(ctx, "t"); c.PEM != "crl" || c.Number != "7" || c.CAID != "" {
		t.Errorf("crl = %+v", c)
	}
	if s, _ := d.Seen(ctx, "t"); !s["ap-1"].Connected {
		t.Errorf("seen = %+v", s)
	}
	if c, _ := d.LogCursor(ctx, "t"); c.IsZero() {
		t.Error("cursor lost")
	}
	// 新しいポートの範囲を受け、外は断る。
	if _, err := d.CreateTenant(ctx, spec("u", 21999)); err != nil {
		t.Errorf("port 21999: %v", err)
	}
	if _, err := d.sql.ExecContext(ctx, `INSERT INTO tenants (id, slug, port, auth_upstream, acct_upstream, created_at, updated_at) VALUES ('v', 'v', 19999, 'x', 'x', 1, 1)`); err == nil {
		t.Error("port 19999 accepted by the CHECK")
	}
	// 外部キーが効いている（親を消すと子が消える）。
	if err := d.DeleteTenant(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if aps, _ := d.APs(ctx, "t"); len(aps) != 0 {
		t.Errorf("aps left: %+v", aps)
	}
}
