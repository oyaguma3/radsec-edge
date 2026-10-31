package edge

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

func TestApplyNeedsEverything(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	tn, err := e.svc.CreateTenant(ctx, e.user, TenantInput{Slug: "tenant-a", Auth: authUp, Acct: acctUp})
	if err != nil {
		t.Fatal(err)
	}
	if tn.Port != 20000 || tn.ID != "tenant-a" {
		t.Errorf("tenant = %+v", tn)
	}
	missing, _ := e.svc.Missing(ctx, tn)
	eq(t, "Missing", missing, []string{"クライアントCA の証明書", "CRL", "サーバー証明書", "ヘルスチェック用の証明書"})
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err == nil || !IsInput(err) || rec.Result != db.ResultFailed || !strings.Contains(err.Error(), "そろっていません") {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("agent was called: %v", calls)
	}
	p, _ := e.svc.Plan(ctx, "tenant-a")
	if p.Ready() {
		t.Error("Plan is ready")
	}
}

func TestApplyFlow(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	tn := e.readyTenant(t, "tenant-a")
	p, err := e.svc.Plan(ctx, "tenant-a")
	if err != nil || !p.Ready() || p.Same || p.Action != rsconf.ActionRestart || len(p.Hunks) == 0 {
		t.Fatalf("Plan = %+v, %v", p, err)
	}

	// 最初の反映: 構文検査 → 作って起動 → ヘルスチェック。
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err != nil || rec.Result != db.ResultOK || rec.Action != agent.EnsureCreated {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"validate tenant-a", "ensure tenant-a"})
	if got := e.probe.Addrs[len(e.probe.Addrs)-1]; got != "radsecproxy-tenant-a:2083" {
		t.Errorf("probe addr = %s", got)
	}
	tn, _ = e.db.Tenant(ctx, "tenant-a")
	if tn.Pending() || tn.AppliedPort != 20000 || tn.AppliedHash != rec.Hash {
		t.Errorf("tenant after apply: pending=%v port=%d hash=%s", tn.Pending(), tn.AppliedPort, tn.AppliedHash)
	}
	if p, _ := e.svc.Plan(ctx, "tenant-a"); !p.Same || len(p.Hunks) != 0 || p.Action != rsconf.ActionNone {
		t.Errorf("Plan after apply = %+v", p)
	}
	// 変わっていなければ、構文検査も再起動もしない。
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil || rec.Action != "none" {
		t.Errorf("Apply(same) = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"ensure tenant-a"})

	// AP を足すと、client ブロックが変わるので再起動する。
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	p, _ = e.svc.Plan(ctx, "tenant-a")
	if p.Action != rsconf.ActionRestart || !strings.Contains(hunkText(p), "+client tenant-a-ap-001 {") {
		t.Errorf("Plan with an AP = %+v\n%s", p, hunkText(p))
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil || rec.Action != "restart" || rec.Version != 5 {
		t.Fatalf("Apply(ap) = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"validate tenant-a", "ensure tenant-a", "restart tenant-a"})

	// CRL の更新は、望む状態の版を上げずに、反映済みの版に入れて SIGHUP する。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 2, Revoked: []*big.Int{big.NewInt(9)}})); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"sighup tenant-a"})
	after, _ := e.db.Tenant(ctx, "tenant-a")
	if after.Pending() || after.DesiredVersion != 5 || after.AppliedHash == tn.AppliedHash {
		t.Errorf("tenant after crl: pending=%v desired=%d hash changed=%v", after.Pending(), after.DesiredVersion, after.AppliedHash != tn.AppliedHash)
	}
	_, cur, _ := e.svc.Store.Current("tenant-a")
	if entries, _ := cur.Trust(); entries[0].CRL.Number.Int64() != 2 {
		t.Errorf("crl in the applied generation = %v", entries[0].CRL.Number)
	}
	applies, _ := e.db.Applies(ctx, "tenant-a", 10)
	if applies[0].Trigger != db.TriggerCRL || applies[0].Result != db.ResultOK {
		t.Errorf("last apply = %+v", applies[0])
	}
	// 古い CRL と、期限の切れた CRL は置かない。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 1})); err == nil {
		t.Error("older CRL accepted")
	}
	now := time.Now()
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 3, ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(-time.Hour)})); err == nil {
		t.Error("expired CRL accepted")
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls after rejected CRLs = %v", calls)
	}
	// 版のディレクトリは 3 つまで。
	entries, _ := os.ReadDir(filepath.Join(e.svc.Store.Root, "tenant-a", rsconf.GenDir))
	if len(entries) > 3 {
		t.Errorf("%d generations left", len(entries))
	}
}

func hunkText(p Plan) string {
	var b strings.Builder
	for _, h := range p.Hunks {
		for _, l := range h.Lines {
			b.WriteByte(byte(l.Op))
			b.WriteString(l.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestApplyRollback(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	goodGen, _, _ := e.svc.Store.Current("tenant-a")
	e.agent.TakeCalls()

	// 構文検査で断られたら、何も変えない。
	e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil)
	e.agent.ValidateOK = false
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err == nil || rec.Result != db.ResultFailed || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("Apply(invalid) = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"validate tenant-a"})
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != goodGen {
		t.Error("current changed after a validation failure")
	}
	e.agent.ValidateOK = true

	// ヘルスチェックが通らなければ、前の版に戻して再起動する。
	e.probe.SetFail(true)
	go func() {
		// 前の版のヘルスチェックは通す（戻した後）。
		time.Sleep(1500 * time.Millisecond)
		e.probe.SetFail(false)
	}()
	e.svc.ProbeTimeout = time.Second
	rec, err = e.svc.Apply(ctx, e.user, "tenant-a")
	if err == nil || rec.Result != db.ResultRolledBack {
		t.Fatalf("Apply(probe fails) = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"validate tenant-a", "ensure tenant-a", "restart tenant-a", "ensure tenant-a", "restart tenant-a"})
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != goodGen {
		t.Error("not rolled back to the previous generation")
	}
	tn, _ := e.db.Tenant(ctx, "tenant-a")
	if !tn.Pending() {
		t.Error("the failed version is marked as applied")
	}
}

func TestFirstApplyFailure(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	e.probe.SetFail(true)
	e.svc.ProbeTimeout = 500 * time.Millisecond
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err == nil || rec.Result != db.ResultRolledBack {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	// 前の版がないので、止めて current を外す（整合ループが壊れた版で起動しない）。
	eq(t, "calls", e.agent.TakeCalls(), []string{"validate tenant-a", "ensure tenant-a", "stop tenant-a"})
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != "" {
		t.Errorf("current = %q", gen)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("reconcile started a broken generation: %v", calls)
	}
}

func TestReconcile(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	e.readyTenant(t, "tenant-b")
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if _, err := e.svc.Apply(ctx, e.user, id); err != nil {
			t.Fatal(err)
		}
	}
	e.agent.TakeCalls()
	// 何も変わっていなければ何もしない。
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls = %v", calls)
	}
	// 手で止めたコンテナは起動し、消えたコンテナは作り直す。未反映の変更（ポート）は反映しない。
	e.agent.Containers["tenant-a"].Running = false
	delete(e.agent.Containers, "tenant-b")
	if _, err := e.svc.UpdateTenant(ctx, e.user, "tenant-b", TenantInput{Port: 20900, Auth: authUp, Acct: acctUp}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"ensure tenant-a", "ensure tenant-b"})
	if p := e.agent.Containers["tenant-b"].Port; p != 20001 {
		t.Errorf("tenant-b port = %d, want the applied port 20001", p)
	}
	// 停止したテナントのコンテナは止める（SetEnabled はすぐに効かせる）。
	if err := e.svc.SetEnabled(ctx, e.user, "tenant-a", false); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"stop tenant-a"})
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); !IsInput(err) {
		t.Errorf("Apply(stopped) = %v", err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls for a stopped tenant = %v", calls)
	}
	if err := e.svc.SetEnabled(ctx, e.user, "tenant-a", true); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"ensure tenant-a"})

	// DB にないテナントのコンテナとディレクトリは片付ける。
	e.agent.Containers["gone"] = &agent.Container{TenantID: "gone", Slug: "gone", Running: true}
	os.MkdirAll(filepath.Join(e.svc.Store.Root, "gone", "gen"), 0o750)
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"remove gone"})
	if _, err := os.Stat(filepath.Join(e.svc.Store.Root, "gone")); !os.IsNotExist(err) {
		t.Error("the directory of a deleted tenant is left")
	}
	if st := e.svc.LastReconcile(); st.At.IsZero() || st.Error != "" {
		t.Errorf("LastReconcile = %+v", st)
	}

	// テナントを消すと、コンテナ・ディレクトリ・鍵も消える。
	if err := e.svc.DeleteTenant(ctx, e.user, "tenant-b"); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"remove tenant-b"})
	if _, err := os.Stat(filepath.Join(e.svc.Store.Root, "tenant-b")); !os.IsNotExist(err) {
		t.Error("tenant dir is left")
	}
	if k, _ := e.svc.Keys.Current("tenant-b", keystore.Server); k != nil {
		t.Error("key is left")
	}
}

func TestRefreshCRL(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()

	var body atomic.Value
	body.Store(e.ca.CRL(t, pkitest.CRL{Number: 5}))
	var hits, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/crl/tenant.tenant-a.pem" {
			http.NotFound(w, r)
			return
		}
		b := body.Load().([]byte)
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(b))
		if r.Header.Get("If-None-Match") == etag {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(b)
	}))
	defer srv.Close()
	e.svc.CRLBaseURL = srv.URL

	if err := e.svc.RefreshCRL(ctx, System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"sighup tenant-a"})
	c, _ := e.db.CRL(ctx, "tenant-a")
	if c.Number != "5" || c.Source != "fetch" || c.ETag == "" || c.LastError != "" {
		t.Errorf("crl = %+v", c)
	}
	// 変わっていなければ 304 で、何もしない。
	if err := e.svc.RefreshCRL(ctx, System, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if notModified.Load() != 1 {
		t.Errorf("304 = %d", notModified.Load())
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls after 304 = %v", calls)
	}
	// 期限の切れた CRL は置かず、取得の誤りとして残す。
	now := time.Now()
	body.Store(e.ca.CRL(t, pkitest.CRL{Number: 6, ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(-time.Hour)}))
	if err := e.svc.RefreshCRL(ctx, System, "tenant-a"); err == nil {
		t.Error("expired CRL accepted")
	}
	c, _ = e.db.CRL(ctx, "tenant-a")
	if c.Number != "5" || !strings.Contains(c.LastError, "期限") {
		t.Errorf("crl after a rejected fetch = %+v", c)
	}
	// 別の CA の CRL（改ざん）も置かない。
	body.Store(e.serverCA.CRL(t, pkitest.CRL{Number: 7}))
	if err := e.svc.RefreshCRL(ctx, System, "tenant-a"); err == nil {
		t.Error("CRL of another CA accepted")
	}
	// 取得先に届かない。
	srv.Close()
	if err := e.svc.RefreshCRL(ctx, System, "tenant-a"); err == nil {
		t.Error("unreachable server accepted")
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls after failures = %v", calls)
	}
	// テナントごとの取得先。
	tn, _ := e.db.Tenant(ctx, "tenant-a")
	tn.CRLURL = "http://192.0.2.1/x.pem"
	if got := e.svc.CRLURL(tn); got != "http://192.0.2.1/x.pem" {
		t.Errorf("CRLURL = %s", got)
	}
}

func TestCertificates(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	s := e.svc

	// エッジで作っていない鍵の証明書は断る。
	_, otherKey := pkitest.NewKeyPair(t)
	csr, _ := pki.NewCSR(otherKey, "x")
	_, cert := e.serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames("tenant-a", "radsec.test"), Server: true}, csr)
	if err := s.ImportCert(ctx, e.user, "tenant-a", keystore.Server, cert); !IsInput(err) {
		t.Errorf("foreign key: %v", err)
	}
	// 同じ鍵での更新は受け付ける。
	key, _ := s.Keys.Current("tenant-a", keystore.Server)
	csr, _ = pki.NewCSR(key, "x")
	_, cert = e.serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames("tenant-a", "radsec.test"), Server: true}, csr)
	if err := s.ImportCert(ctx, e.user, "tenant-a", keystore.Server, cert); err != nil {
		t.Errorf("renewal with the same key: %v", err)
	}
	// ヘルスチェック用の証明書は、テナントのクライアントCA が発行した probe の SAN のもの。
	csr, _ = s.CSR(ctx, e.user, "tenant-a", keystore.Probe)
	_, cert = e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", "tenant-a", "ap-001")}, csr)
	if err := s.ImportCert(ctx, e.user, "tenant-a", keystore.Probe, cert); !IsInput(err) {
		t.Errorf("probe cert with a wrong SAN: %v", err)
	}
	// AP の証明書は任意。取り込むときは SAN を確かめる。
	_, apKey := pkitest.NewKeyPair(t)
	csr, _ = pki.NewCSR(apKey, "x")
	apCert, apPEM := e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", "tenant-a", "ap-001")}, csr)
	ap, err := s.PutAP(ctx, e.user, "tenant-a", "ap-001", apPEM)
	if err != nil || ap.CertSerial != pki.SerialHex(apCert) || ap.NASID != "tenant-a-ap-001" {
		t.Errorf("PutAP = %+v, %v", ap, err)
	}
	if _, err := s.PutAP(ctx, e.user, "tenant-a", "ap-002", apPEM); !IsInput(err) {
		t.Errorf("AP cert of another AP: %v", err)
	}
	if _, err := s.PutAP(ctx, e.user, "tenant-a", "probe", nil); !IsInput(err) {
		t.Errorf("reserved name: %v", err)
	}
	// CA を取り替えると、前の CA の CRL は捨てる。
	other := pkitest.NewCA(t, "new CA")
	if err := s.ImportClientCA(ctx, e.user, "tenant-a", other.PEM); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.db.CRL(ctx, "tenant-a"); c.PEM != "" {
		t.Error("CRL of the old CA is left")
	}
	if err := s.ImportClientCA(ctx, e.user, "tenant-a", apPEM); !IsInput(err) {
		t.Errorf("leaf as CA: %v", err)
	}
	if _, err := s.CreateTenant(ctx, e.user, TenantInput{Slug: "tenant-a", Auth: authUp, Acct: acctUp}); !IsInput(err) {
		t.Errorf("duplicate tenant: %v", err)
	}
	if err := s.DeleteTenant(ctx, e.user, "none"); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("DeleteTenant(none) = %v", err)
	}
}

// brought は持ち込みの CA の宣言を作る。
func brought(slug, name string, ca *pkitest.CA, hasCRL bool) BroughtInput {
	return BroughtInput{CAID: "brought." + slug + "." + name, CertPEM: ca.PEM, HasCRL: hasCRL}
}

func TestSetTrust(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	vendor := pkitest.NewCA(t, "vendor org CA")
	bad := map[string]TrustInput{
		"wrong slug":           {Brought: []BroughtInput{brought("tenant-b", "v", vendor, true)}},
		"bad id":               {Brought: []BroughtInput{{CAID: "tenant.tenant-a", CertPEM: vendor.PEM, HasCRL: true}}},
		"bad cert":             {Brought: []BroughtInput{{CAID: "brought.tenant-a.v", CertPEM: []byte("x"), HasCRL: true}}},
		"same subject":         {Brought: []BroughtInput{brought("tenant-a", "v", pkitest.NewCA(t, "tenant-a client CA"), true)}},
		"same subject between": {Brought: []BroughtInput{brought("tenant-a", "a", vendor, true), brought("tenant-a", "b", pkitest.NewCA(t, "vendor org CA"), true)}},
		"no match":             {Brought: []BroughtInput{brought("tenant-a", "v", vendor, false)}},
		"bad match":            {Brought: []BroughtInput{brought("tenant-a", "v", vendor, true)}, SharedMatch: rsconf.Match{Attr: "CN", Pattern: "a"}},
		"many cidrs":           {SourceCIDRs: make([]netip.Prefix, rsconf.MaxSourceCIDRs+1)},
		"invalid cidr":         {SourceCIDRs: []netip.Prefix{{}}},
	}
	for name, in := range bad {
		if err := e.svc.SetTrust(ctx, e.user, "tenant-a", in); !IsInput(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if list, _ := e.db.BroughtCAs(ctx, "tenant-a"); len(list) != 0 {
		t.Fatalf("left: %+v", list)
	}
	// CRL がそろうまで反映できない。
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "v", vendor, true)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err == nil || !strings.Contains(err.Error(), "brought.tenant-a.v の CRL") {
		t.Fatalf("Apply without the CRL: %v", err)
	}
	// 別の CA の CRL は断る。
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.v", e.ca.CRL(t, pkitest.CRL{Number: 1})); !IsInput(err) {
		t.Errorf("crl of another CA: %v", err)
	}
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.none", vendor.CRL(t, pkitest.CRL{Number: 1})); !IsInput(err) {
		t.Errorf("unknown CA: %v", err)
	}
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.v", vendor.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	_, b, _ := e.svc.Store.Current("tenant-a")
	conf := string(b[rsconf.FileConf])
	for _, want := range []string{"client shared {", "addVendorAttribute 32473:1:'tenant-a", "CRLCheck on"} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf does not contain %q:\n%s", want, conf)
		}
	}
}

func TestPutGroup(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.PutGroup(ctx, e.user, "tenant-a", "probe", "box", nil); !IsInput(err) {
		t.Errorf("probe: %v", err)
	}
	if _, err := e.svc.PutGroup(ctx, e.user, "tenant-a", "g", "fax", nil); !IsInput(err) {
		t.Errorf("purpose: %v", err)
	}
	_, key := pkitest.NewKeyPair(t)
	csr, _ := pki.NewCSR(key, "x")
	// AP の SAN の証明書はグループに使えない。
	_, wrong := e.ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a-g", URI: names.SANURI("example", "tenant-a", "g")}, csr)
	if _, err := e.svc.PutGroup(ctx, e.user, "tenant-a", "g", "unifi", wrong); !IsInput(err) {
		t.Errorf("wrong SAN: %v", err)
	}
	c, cert := e.ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a-g", URI: names.GroupSANURI("example", "tenant-a", "g")}, csr)
	got, err := e.svc.PutGroup(ctx, e.user, "tenant-a", "g", "unifi", cert)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertSerial != pki.SerialHex(c) || got.Kind != db.KindGroup || got.NASID != "tenant-a-g" {
		t.Errorf("group = %+v", got)
	}
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "g", nil); !errors.Is(err, db.ErrConflict) && !IsInput(err) {
		t.Errorf("AP named like a group: %v", err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	_, b, _ := e.svc.Store.Current("tenant-a")
	if !strings.Contains(string(b[rsconf.FileConf]), "client grp-g {") {
		t.Errorf("no group block:\n%s", b[rsconf.FileConf])
	}
}

// 送信元の範囲があるテナントでは、ヘルスチェックのブロックはテナントのネットワークのサブネットだけを許す。
func TestSourceCIDRs(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{SourceCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}); err != nil {
		t.Fatal(err)
	}
	// サブネットが分からなければ反映しない。
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err == nil || !strings.Contains(err.Error(), "サブネット") {
		t.Fatalf("no subnet: %v", err)
	}
	e.agent.NetworkSubnets = []string{"172.31.83.0/24"}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	_, b, _ := e.svc.Store.Current("tenant-a")
	conf := string(b[rsconf.FileConf])
	ap, probe, _ := strings.Cut(conf[strings.Index(conf, "client tenant-a-ap-001"):], "client tenant-a-probe")
	if !strings.Contains(ap, "host 203.0.113.0/24") || strings.Contains(ap, "0.0.0.0/0") {
		t.Errorf("AP block:\n%s", ap)
	}
	if !strings.Contains(probe, "host 172.31.83.0/24") || strings.Contains(probe, "203.0.113") {
		t.Errorf("probe block:\n%s", probe)
	}
}

// CRL が切れた CA があるときの動き（§24.5）。
func TestExpiredCRLs(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	now := time.Now()
	e.svc.Now = func() time.Time { return now }
	e.readyTenant(t, "tenant-a")
	vendor := pkitest.NewCA(t, "vendor org CA")
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "v", vendor, true)}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.v", vendor.CRL(t, pkitest.CRL{Number: 1, NextUpdate: now.Add(time.Hour)})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	// 持ち込みの CA の CRL が切れても、発行した CA の新しい CRL は置いて SIGHUP する（失効の反映を優先する）。
	now = now.Add(2 * time.Hour)
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 2})); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); !slices.Contains(calls, "sighup tenant-a") {
		t.Errorf("no SIGHUP for the issued CRL: %v", calls)
	}
	_, b, _ := e.svc.Store.Current("tenant-a")
	entries, _ := b.Trust()
	if entries[0].CRL.Number.Int64() != 2 || entries[1].CRL.Number.Int64() != 1 {
		t.Errorf("bundle: %v %v", entries[0].CRL.Number, entries[1].CRL.Number)
	}
	// 反映も止めない（こちらの AP の追加など）。
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Errorf("Apply with an expired brought CRL: %v", err)
	}
	// 持ち込みの CA の CRL は切れたものを置けない。
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.v", vendor.CRL(t, pkitest.CRL{Number: 2, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)})); !IsInput(err) {
		t.Errorf("expired brought CRL: %v", err)
	}
	// 発行した CA の CRL が切れていれば、持ち込みの CA の新しい CRL は DB に置くが、読み込ませない（こちらの AP が切れるため）。
	now = now.Add(30 * 24 * time.Hour)
	e.agent.TakeCalls()
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.v", vendor.CRL(t, pkitest.CRL{Number: 3, NextUpdate: now.Add(24 * time.Hour)})); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); slices.Contains(calls, "sighup tenant-a") {
		t.Errorf("SIGHUP with an expired issued CRL: %v", calls)
	}
	if c, _ := e.db.CRLOf(ctx, "tenant-a", "brought.tenant-a.v"); c.Number != "3" {
		t.Errorf("CRL is not stored: %+v", c.Number)
	}
	// 発行した CA の CRL が切れていれば反映は断る。
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err == nil || !strings.Contains(err.Error(), "期限") {
		t.Errorf("Apply with an expired issued CRL: %v", err)
	}
	// 発行した CA の新しい CRL が届いて、次の取得の後に持ち込みの CA の CRL も入る。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 3, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(7 * 24 * time.Hour)})); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); !slices.Contains(calls, "sighup tenant-a") {
		t.Errorf("no SIGHUP after renewal: %v", calls)
	}
}

// CRL は CA ごとに取りに行き、1 つの CA で失敗しても、ほかの CA は続ける（§24.5）。
func TestRefreshPerCA(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	vendor := pkitest.NewCA(t, "vendor org CA")
	none := pkitest.NewCA(t, "no crl")
	bodies := map[string][]byte{}
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		b, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	e.svc.CRLBaseURL = srv.URL
	e.readyTenant(t, "tenant-a")
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "v", vendor, true), brought("tenant-a", "n", none, false)},
		SharedMatch: rsconf.Match{Attr: "CN", Pattern: "^[a-f0-9]{12}$"}}); err != nil {
		t.Fatal(err)
	}
	// 発行した CA の口が止まっていても、持ち込みの CA の CRL は取る。CRL のない CA には取りに行かない。
	bodies["/crl/brought.tenant-a.v.pem"] = vendor.CRL(t, pkitest.CRL{Number: 4})
	err := e.svc.RefreshCRL(ctx, e.user, "tenant-a")
	if err == nil {
		t.Error("the failure of the issued CA is not reported")
	}
	eq(t, "paths", hits, []string{"/crl/tenant.tenant-a.pem", "/crl/brought.tenant-a.v.pem"})
	if c, _ := e.db.CRLOf(ctx, "tenant-a", "brought.tenant-a.v"); c.Number != "4" {
		t.Errorf("brought CRL = %+v", c)
	}
	if c, _ := e.db.CRL(ctx, "tenant-a"); c.LastError == "" {
		t.Error("the failure is not recorded")
	}
}
