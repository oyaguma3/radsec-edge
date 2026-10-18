package edge

import (
	"math/big"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

// クライアントCA を差し替えて、ヘルスチェック用の証明書を出し直さないまま反映しようとすると、反映の前に断る（§22.4 の 1）。
func TestApplyRefusesProbeOfAnotherCA(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	other := pkitest.NewCA(t, "other CA")
	if err := e.svc.ImportClientCA(ctx, e.user, "tenant-a", other.PEM); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", other.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	p, _ := e.svc.Plan(ctx, "tenant-a")
	if p.Ready() || !strings.Contains(p.Error, "今のクライアントCA で検証できません") {
		t.Errorf("Plan = %+v", p)
	}
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if !IsInput(err) || !strings.Contains(err.Error(), "今のクライアントCA で検証できません") || rec.Result != db.ResultFailed {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	if calls := e.agent.TakeCalls(); len(calls) != 0 {
		t.Errorf("the container was touched: %v", calls)
	}
	tn, _ := e.db.Tenant(ctx, "tenant-a")
	if msg, _ := e.svc.ProbeProblem(ctx, tn); msg == "" {
		t.Error("ProbeProblem is empty")
	}
}

// ヘルスチェック用の証明書を失効させた CRL も、戻さずに置いて SIGHUP する（AP の失効を止めない）。出し直すまで反映は断る（§22.4 の 2）。
func TestCRLRevokingProbe(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	tn := e.readyTenant(t, "tenant-a")
	e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil)
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	probe, _ := pki.ParseCert([]byte(tn.ProbeCertPEM))
	// Status-Server を送ったら失敗させる（送らずに、コンテナが動いていることだけを確かめること）。
	e.probe.SetFail(true)
	before := len(e.probe.Addrs)
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 2, Revoked: []*big.Int{probe.SerialNumber, big.NewInt(77)}})); err != nil {
		t.Fatalf("InstallCRL = %v", err)
	}
	eq(t, "calls", e.agent.TakeCalls(), []string{"sighup tenant-a"})
	if len(e.probe.Addrs) != before {
		t.Error("Status-Server was sent with a revoked probe certificate")
	}
	_, cur, _ := e.svc.Store.Current("tenant-a")
	if _, crl, _ := cur.Trust(); crl.Number.Int64() != 2 {
		t.Errorf("the CRL was not pushed: #%v", crl.Number)
	}
	applies, _ := e.db.Applies(ctx, "tenant-a", 1)
	if applies[0].Trigger != db.TriggerCRL || applies[0].Result != db.ResultOK {
		t.Errorf("crl apply = %+v", applies[0])
	}
	tn, _ = e.db.Tenant(ctx, "tenant-a")
	if msg, _ := e.svc.ProbeProblem(ctx, tn); !strings.Contains(msg, "失効しています") {
		t.Errorf("ProbeProblem = %q", msg)
	}
	// 次の CRL（AP の失効など）も置ける。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 3, Revoked: []*big.Int{probe.SerialNumber, big.NewInt(77), big.NewInt(78)}})); err != nil {
		t.Fatalf("next InstallCRL = %v", err)
	}
	// 出し直すまで反映は断る。
	e.svc.PutAP(ctx, e.user, "tenant-a", "ap-002", nil)
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); !IsInput(err) || !strings.Contains(err.Error(), "失効しています") {
		t.Fatalf("Apply with a revoked probe = %v", err)
	}
	// 出し直すと反映できる。
	e.probe.SetFail(false)
	csr, _ := e.svc.CSR(ctx, e.user, "tenant-a", keystore.Probe)
	_, cert := e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", "tenant-a", "probe")}, csr)
	if err := e.svc.ImportCert(ctx, e.user, "tenant-a", keystore.Probe, cert); err != nil {
		t.Fatal(err)
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil || rec.Result != db.ResultOK {
		t.Fatalf("Apply after reissuing = %+v, %v", rec, err)
	}
}
