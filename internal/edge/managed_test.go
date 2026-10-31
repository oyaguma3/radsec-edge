package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

func (e *env) declaration(rev int64, aps ...APDecl) Declaration {
	return Declaration{ID: "42", Slug: "tenant-a", Revision: rev, Port: 20042, Auth: authUp, Acct: acctUp, IssuedCAID: "tenant.tenant-a", IssuedCAPEM: e.ca.PEM, APs: aps}
}

func TestDeclareVersions(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	res, err := e.svc.Declare(ctx, e.user, e.declaration(5, APDecl{Name: "ap-001", Kind: db.KindAP}))
	if err != nil || !res.Created || !res.Changed || res.Tenant.Revision != 5 || res.Tenant.DesiredVersion != 1 {
		t.Fatalf("Declare = %+v, %v", res, err)
	}
	// 同じ中身なら内部の版を上げず、版だけ覚える（古い版でも断らない。EA3）。
	res, err = e.svc.Declare(ctx, e.user, e.declaration(3, APDecl{Name: "ap-001", Kind: db.KindAP}))
	if err != nil || res.Created || res.Changed || res.Tenant.Revision != 3 || res.Tenant.DesiredVersion != 1 {
		t.Fatalf("Declare(same) = %+v, %v", res, err)
	}
	// 表示だけの違いも上げないが、値は書き換える。
	res, err = e.svc.Declare(ctx, e.user, e.declaration(4, APDecl{Name: "ap-001", Kind: db.KindAP, CertSerial: "ab", CertNotAfter: time.Unix(2000000000, 0)}))
	if err != nil || res.Changed || res.Tenant.DesiredVersion != 1 {
		t.Fatalf("Declare(display) = %+v, %v", res, err)
	}
	aps, _ := e.db.APs(ctx, "42")
	if len(aps) != 1 || aps[0].CertSerial != "ab" || aps[0].NASID != "tenant-a-ap-001" {
		t.Errorf("aps = %+v", aps)
	}
	// 種類の違いは設定に効く。
	res, err = e.svc.Declare(ctx, e.user, e.declaration(6, APDecl{Name: "ap-001", Kind: db.KindGroup, Purpose: "unifi"}))
	if err != nil || !res.Changed || res.Tenant.DesiredVersion != 2 {
		t.Fatalf("Declare(kind) = %+v, %v", res, err)
	}
	// 持ち込みの CA の同じ Subject を断る（発行した CA と同じ）。
	d := e.declaration(7)
	d.Trust.Brought = []BroughtInput{{CAID: "brought.tenant-a.v", CertPEM: e.ca.PEM, HasCRL: true}}
	if _, err := e.svc.Declare(ctx, e.user, d); !IsInput(err) {
		t.Errorf("same subject = %v", err)
	}
	// 持ち込みの CA を足すと設定が変わり、発行した CA を替えると CRL が消える。
	vendor := pkitest.NewCA(t, "vendor CA")
	d = e.declaration(8)
	d.Trust.Brought = []BroughtInput{{CAID: "brought.tenant-a.v", CertPEM: vendor.PEM, HasCRL: true}}
	if res, err = e.svc.Declare(ctx, e.user, d); err != nil || !res.Changed {
		t.Fatalf("Declare(brought) = %+v, %v", res, err)
	}
	if err := e.svc.InstallCRL(ctx, e.user, "42", e.ca.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	other := pkitest.NewCA(t, "another client CA")
	d.IssuedCAPEM = other.PEM
	if res, err = e.svc.Declare(ctx, e.user, d); err != nil || !res.Changed {
		t.Fatalf("Declare(ca) = %+v, %v", res, err)
	}
	if c, _ := e.db.CRL(ctx, "42"); c.PEM != "" {
		t.Error("the CRL of the old CA is left")
	}
	// slug は変えられない。上限を超える新しいテナントは断る。
	d.Slug, d.IssuedCAID, d.Trust = "tenant-b", "tenant.tenant-b", TrustInput{}
	var ie *InputError
	if _, err := e.svc.Declare(ctx, e.user, d); !errors.As(err, &ie) || ie.Cause != CauseSlugImmutable {
		t.Errorf("slug = %v", err)
	}
	e.svc.Capacity = 1
	d.ID, d.Port = "43", 20043
	if _, err := e.svc.Declare(ctx, e.user, d); !errors.As(err, &ie) || ie.Cause != CauseCapacityExceeded {
		t.Errorf("capacity = %v", err)
	}
	if _, err := e.svc.CreateTenant(ctx, e.user, TenantInput{Slug: "standalone", Auth: authUp, Acct: acctUp}); !errors.As(err, &ie) || ie.Cause != CauseCapacityExceeded {
		t.Errorf("capacity (standalone) = %v", err)
	}
}

// interrupt は、反映の途中で落ちたのと同じ状態を作る（新しい版を current にしたまま、反映済みにしていない）。
func (e *env) interrupt(t *testing.T, id string) string {
	t.Helper()
	ctx := t.Context()
	tn, err := e.db.Tenant(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.svc.render(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := e.svc.Store.Stage(tn.Slug, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Store.Activate(tn.Slug, gen); err != nil {
		t.Fatal(err)
	}
	return gen
}

func TestRecoverInterrupted(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")

	// 最初の反映の途中で落ちた: 反映済みの版がないので、止めて current を外す。
	e.interrupt(t, "tenant-a")
	if _, err := e.svc.Agent.Ensure(ctx, "tenant-a", "tenant-a", 20000); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != "" {
		t.Errorf("current = %q", gen)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"stop tenant-a"})
	last, err := e.db.LastApply(ctx, "tenant-a")
	if err != nil || last.Result != db.ResultInterrupted {
		t.Fatalf("LastApply = %+v, %v", last, err)
	}

	// 反映した後に、次の反映の途中で落ちた: 反映済みの版に戻して再起動する。
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	good, _, _ := e.svc.Store.Current("tenant-a")
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	e.interrupt(t, "tenant-a")
	e.agent.TakeCalls()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != good {
		t.Errorf("current = %q, want %q", gen, good)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"ensure tenant-a", "restart tenant-a"})
	if last, _ := e.db.LastApply(ctx, "tenant-a"); last.Result != db.ResultInterrupted {
		t.Errorf("LastApply = %+v", last)
	}
	// 直った後は何もしない。
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("calls = %v", calls)
	}

	// 整合ループより先に反映が来ても、前の版に戻してから反映する（AP の client ブロックが読まれる）。
	e.interrupt(t, "tenant-a")
	e.agent.TakeCalls()
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err != nil || rec.Action != "restart" || rec.Result != db.ResultOK {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"ensure tenant-a", "restart tenant-a", "validate tenant-a", "ensure tenant-a", "restart tenant-a"})

	// 停止しているテナントは起動しない（版だけ戻す）。
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-002", nil); err != nil {
		t.Fatal(err)
	}
	good, _, _ = e.svc.Store.Current("tenant-a")
	if err := e.svc.SetEnabled(ctx, e.user, "tenant-a", false); err != nil {
		t.Fatal(err)
	}
	e.interrupt(t, "tenant-a")
	e.agent.TakeCalls()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != good {
		t.Errorf("stopped: current = %q, want %q", gen, good)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("stopped: calls = %v", calls)
	}
}

// 反映済みの版のディレクトリがなければ（古い DB に戻したときなど）、戻せないので、次の反映で再起動して読み込ませる。
func TestRecoverGenerationGone(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	tn, _ := e.db.Tenant(ctx, "tenant-a")
	if err := e.db.MarkApplied(ctx, "tenant-a", tn.AppliedVersion, tn.AppliedRevision, "ffffffffffffffffffffffff", tn.AppliedPort); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err != nil || rec.Action != "restart" {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
}

func TestStartApplyAndShutdown(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	good, _, _ := e.svc.Store.Current("tenant-a")
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	// ヘルスチェックの途中で止める。Shutdown で取り消され、前の版に戻す。
	entered := make(chan struct{}, 1)
	var calls int
	e.svc.Probe = func(c context.Context, _ string, _ tls.Certificate, _ *x509.Certificate) error {
		calls++
		if calls > 1 {
			return nil // 前の版のヘルスチェック
		}
		entered <- struct{}{}
		<-c.Done()
		return c.Err()
	}
	e.svc.ProbeTimeout = 30 * time.Second
	started, err := e.svc.StartApply(ctx, e.user, "tenant-a")
	if err != nil || !started {
		t.Fatalf("StartApply = %v, %v", started, err)
	}
	<-entered
	if _, running := e.svc.ApplyRunning("tenant-a"); !running {
		t.Error("not running")
	}
	if started, err := e.svc.StartApply(ctx, e.user, "tenant-a"); err != nil || started {
		t.Errorf("StartApply(again) = %v, %v", started, err)
	}
	// 排他は取れない。
	if err := e.svc.Restart(WithLockWait(ctx, 10*time.Millisecond), e.user, "tenant-a"); !errors.Is(err, ErrBusy) {
		t.Errorf("Restart = %v", err)
	}
	e.svc.Shutdown(5 * time.Second)
	if _, running := e.svc.ApplyRunning("tenant-a"); running {
		t.Error("still running")
	}
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != good {
		t.Errorf("current = %q, want %q", gen, good)
	}
	if last, _ := e.db.LastApply(ctx, "tenant-a"); last.Result != db.ResultRolledBack {
		t.Errorf("LastApply = %+v", last)
	}
}

func TestAgentStatusCache(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	now := time.Unix(1000, 0)
	e.svc.Now = func() time.Time { return now }
	if _, err := e.svc.AgentStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Agent.Ensure(ctx, "x", "x", 20000); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.AgentStatus(ctx)
	if _, ok := st.Container("x"); ok {
		t.Error("the status was not cached")
	}
	now = now.Add(statusCacheFor + time.Second)
	st, _ = e.svc.AgentStatus(ctx)
	if _, ok := st.Container("x"); !ok {
		t.Error("the cache did not expire")
	}
	// コンテナを変えたら写しを捨てる。
	if _, err := e.svc.Agent.Ensure(ctx, "y", "y", 20001); err != nil {
		t.Fatal(err)
	}
	e.svc.forgetStatus()
	st, _ = e.svc.AgentStatus(ctx)
	if _, ok := st.Container("y"); !ok {
		t.Error("forgetStatus did not work")
	}
}
