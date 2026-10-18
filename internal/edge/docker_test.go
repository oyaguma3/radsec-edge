package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/docker"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/probe"
)

// dockerEnv は本物の agent・Docker・radsecproxy を使う試験の環境を作る（EDGE_TEST_DOCKER=1 のときだけ）。
// ヘルスチェックは、公開したポート（127.0.0.1:<port>）につなぐ。
func dockerEnv(t *testing.T) *env {
	t.Helper()
	if os.Getenv("EDGE_TEST_DOCKER") != "1" {
		t.Skip("EDGE_TEST_DOCKER=1 のときだけ動かす")
	}
	var rnd [4]byte
	rand.Read(rnd[:])
	network := "radsec-edge-test-" + hex.EncodeToString(rnd[:])
	if out, err := exec.Command("docker", "network", "create", network).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "network="+network).Output()
		for id := range strings.FieldsSeq(string(ids)) {
			exec.Command("docker", "rm", "-f", id).Run()
		}
		exec.Command("docker", "network", "rm", network).Run()
	})
	e := newEnv(t)
	tenantsDir := t.TempDir()
	os.Chmod(tenantsDir, 0o755)
	// 試験ではファイルは試験を動かす利用者のものなので、radsecproxy（10083）が読めるようにする。
	e.svc.Store.Root, e.svc.Store.DirMode, e.svc.Store.FileMode = tenantsDir, 0o755, 0o644

	srv := agent.NewServer(agent.ServerOptions{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		Docker: docker.New("/var/run/docker.sock"), TenantsDir: tenantsDir, Network: network})
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Routes()}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	e.svc.Agent = agent.NewClient(sock)
	e.svc.Probe = probe.Check
	e.svc.ProbeTimeout = 15 * time.Second
	e.svc.ProbeAddr = func(_ string, port int) string { return "127.0.0.1:" + strconv.Itoa(port) }
	return e
}

// apProbe は AP の証明書で Status-Server を送る（AP がつながるかの確かめ）。
func apProbe(t *testing.T, e *env, port int, certPEM, keyPEM []byte) error {
	t.Helper()
	tn, _ := e.db.Tenant(t.Context(), "tenant-a")
	srv, _ := pki.ParseCert([]byte(tn.ServerCertPEM))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return probe.Check(t.Context(), "127.0.0.1:"+strconv.Itoa(port), cert, srv)
}

func TestDockerApply(t *testing.T) {
	e := dockerEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	tn, err := e.svc.UpdateTenant(ctx, e.user, "tenant-a", TenantInput{Port: 20990, Auth: authUp, Acct: acctUp})
	if err != nil {
		t.Fatal(err)
	}

	// 最初の反映（本物の radsecproxy の構文検査、作成、Status-Server によるヘルスチェック）。
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if err != nil {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}

	// AP を登録して反映すると（再起動）、AP の証明書でつながる。
	_, apKey := pkitest.NewKeyPair(t)
	csr, _ := pki.NewCSR(apKey, "x")
	apCert, apPEM := e.ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a-ap-001", URI: names.SANURI("example", "tenant-a", "ap-001")}, csr)
	if err := apProbe(t, e, tn.Port, apPEM, apKey); err == nil {
		t.Fatal("an unregistered AP connected")
	}
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", apPEM); err != nil {
		t.Fatal(err)
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil || rec.Action != "restart" {
		t.Fatalf("Apply(ap) = %+v, %v", rec, err)
	}
	if err := apProbe(t, e, tn.Port, apPEM, apKey); err != nil {
		t.Fatalf("registered AP: %v", err)
	}
	// AP の最後の接続（ログの接続の確立と切断の行。設計概要 §12.1）。
	checkSeen(t, e, func(s SeenState) bool { return s.Known && !s.LastUp.IsZero() && !s.LastDown.IsZero() && s.LastIP != "" })

	// AP の証明書を失効させた CRL を入れると、SIGHUP で効き、AP はつながらなくなる（ヘルスチェックは通る）。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 2, Revoked: []*big.Int{apCert.SerialNumber}})); err != nil {
		t.Fatal(err)
	}
	applies, _ := e.db.Applies(ctx, "tenant-a", 1)
	if applies[0].Trigger != db.TriggerCRL || applies[0].Result != db.ResultOK {
		t.Errorf("crl apply = %+v", applies[0])
	}
	if err := apProbe(t, e, tn.Port, apPEM, apKey); err == nil {
		t.Error("a revoked AP connected")
	}
	// 失効させた証明書の拒否も残る（verify error の CN）。
	checkSeen(t, e, func(s SeenState) bool { return !s.LastReject.IsZero() })

	// ヘルスチェックが通らなければ、前の版に戻して再起動する（本物のコンテナで戻す）。
	goodGen, _, _ := e.svc.Store.Current("tenant-a")
	realProbe := e.svc.Probe
	// 新しい版を使っている間は失敗させる（壊れた版の代わり）。
	e.svc.Probe = func(ctx_ context.Context, addr string, c tls.Certificate, s *x509.Certificate) error {
		if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != goodGen {
			return errors.New("injected failure")
		}
		return realProbe(ctx_, addr, c, s)
	}
	e.svc.ProbeTimeout = 2 * time.Second
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-002", nil); err != nil {
		t.Fatal(err)
	}
	rec, err = e.svc.Apply(ctx, e.user, "tenant-a")
	if err == nil || rec.Result != db.ResultRolledBack || strings.Contains(err.Error(), "前の版に戻すのにも失敗") {
		t.Fatalf("Apply(probe fails) = %+v, %v", rec, err)
	}
	if gen, _, _ := e.svc.Store.Current("tenant-a"); gen != goodGen {
		t.Error("not rolled back")
	}
	e.svc.Probe, e.svc.ProbeTimeout = realProbe, 15*time.Second

	// 手で止めたコンテナは、整合ループが起動する。
	if out, err := exec.Command("docker", "stop", agent.ContainerName("tenant-a")).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v\n%s", err, out)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	applies, _ = e.db.Applies(ctx, "tenant-a", 1)
	if applies[0].Trigger != db.TriggerReconcile || applies[0].Action != agent.EnsureStarted || applies[0].Result != db.ResultOK {
		t.Errorf("reconcile = %+v", applies[0])
	}

	// テナントを消すと、コンテナも消える。
	if err := e.svc.DeleteTenant(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Agent.Status(ctx)
	if _, ok := st.Container("tenant-a"); ok {
		t.Error("container is left")
	}
}

// checkSeen は、ログを読んで ap-001 の接続の状態が ok になるのを待つ（ログは少し遅れて届く）。
func checkSeen(t *testing.T, e *env, ok func(SeenState) bool) {
	t.Helper()
	var last SeenState
	for range 20 {
		if err := e.svc.RefreshLastSeen(t.Context()); err != nil {
			t.Fatal(err)
		}
		st, _ := e.svc.Agent.Status(t.Context())
		c, _ := st.Container("tenant-a")
		seen, err := e.svc.APSeen(t.Context(), "tenant-a", c.StartedAt)
		if err != nil {
			t.Fatal(err)
		}
		if last = seen["ap-001"]; ok(last) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := e.svc.Agent.Logs(t.Context(), "tenant-a", 50)
	t.Fatalf("ap-001 seen = %+v\n%s", last, logs)
}
