package edge

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// idleFor は AP の役でつなぎ、何も送らずに読んで、サーバーが接続を閉じるまでの時間を返す（wait の間に閉じなければ false）。
func idleFor(t *testing.T, port int, kc keyCert, wait time.Duration) (time.Duration, bool) {
	t.Helper()
	var c *rsConn
	var err error
	// 作り直しや再起動の直後は、まだ待ち受けていない。
	for deadline := time.Now().Add(15 * time.Second); ; {
		if c, err = dialRS(port, kc); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.close()
	start := time.Now()
	c.c.SetReadDeadline(start.Add(wait))
	_, err = c.c.Read(make([]byte, 1))
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return 0, false
	}
	if err == nil {
		t.Fatal("the server sent data without a request")
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "close") && !strings.Contains(err.Error(), "reset") {
		t.Logf("read ended with %v", err)
	}
	return time.Since(start), true
}

// TestDockerIdleTimeout は、ひな形の版 2 の設定（client ブロックの IdleTimeout 0）で、要求のない AP の接続を閉じないことと、
// パッチの IdleTimeout が効くこと（小さな値なら閉じる）を、本物の radsecproxy で確かめる（§24.15。aka-mvpset の A6-13）。
// 無改造の radsecproxy は 15 分（900 秒）で閉じ、つなぎ直しの遅い AP では Session-Timeout の認証し直しがその分遅れた。
func TestDockerIdleTimeout(t *testing.T) {
	e := dockerEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	tn, err := e.svc.UpdateTenant(ctx, e.user, "tenant-a", TenantInput{Port: 20993, Auth: authUp, Acct: acctUp})
	if err != nil {
		t.Fatal(err)
	}
	_, apKey := pkitest.NewKeyPair(t)
	csr, _ := pki.NewCSR(apKey, "x")
	_, apPEM := e.ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a-ap-001", URI: names.SANURI("example", "tenant-a", "ap-001")}, csr)
	pair, err := tls.X509KeyPair(apPEM, apKey)
	if err != nil {
		t.Fatal(err)
	}
	ap := keyCert{cert: pair}
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", apPEM); err != nil {
		t.Fatal(err)
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	tn = e.tenant(t, "tenant-a")
	if tn.Template != agent.LatestTemplate || agent.LatestTemplate != 2 {
		t.Fatalf("template = %d", tn.Template)
	}
	_, b, err := e.svc.Store.Current("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b[rsconf.FileConf])
	if !strings.Contains(conf, "\n    IdleTimeout 0\n") {
		t.Fatalf("no IdleTimeout 0 in the config:\n%s", conf)
	}

	// IdleTimeout 0: 何も送らない接続を閉じない（小さな値で閉じる時間の 3 倍待つ）。
	if d, closed := idleFor(t, tn.Port, ap, 6*time.Second); closed {
		logs, _ := e.svc.Agent.Logs(ctx, "tenant-a", 20)
		t.Fatalf("the server closed an idle connection after %s with IdleTimeout 0\n%s", d, logs)
	}

	// IdleTimeout 2: パッチが値を読んで、何も送らない接続を 2 秒で閉じる（設定を書き換えて再起動する。製品は 0 しか書かない）。
	b[rsconf.FileConf] = []byte(strings.ReplaceAll(conf, "\n    IdleTimeout 0\n", "\n    IdleTimeout 2\n"))
	gen, err := e.svc.Store.Stage(tn.Slug, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Store.Activate(tn.Slug, gen); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Agent.Restart(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	d, closed := idleFor(t, tn.Port, ap, 10*time.Second)
	if !closed || d < 1500*time.Millisecond || d > 6*time.Second {
		t.Fatalf("with IdleTimeout 2 the server closed = %v after %s", closed, d)
	}
	out, _ := exec.Command("docker", "logs", agent.ContainerName("tenant-a")).CombinedOutput()
	if !strings.Contains(string(out), "client tenant-a-ap-001 (no requests), closing connection") {
		t.Errorf("no idle timeout line in the logs:\n%s", out)
	}
}
