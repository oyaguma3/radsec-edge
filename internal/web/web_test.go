package web

import (
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/access"
	"github.com/oyaguma3/radsec-edge/internal/auth"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/edge/edgetest"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

type testEnv struct {
	srv      *httptest.Server
	db       *db.DB
	agent    *edgetest.FakeAgent
	ca       *pkitest.CA
	serverCA *pkitest.CA
}

func newTestEnv(t *testing.T, ident auth.Identifier) *testEnv {
	t.Helper()
	d, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fa := edgetest.NewFakeAgent()
	probe := &edgetest.FakeProbe{}
	svc := edge.New(edge.Options{Log: log, DB: d, Agent: fa, Store: rsconf.Store{Root: t.TempDir()}, Keys: keystore.Store{Dir: t.TempDir()},
		URNPrefix: "example", DNSDomain: "radsec.test", Secret: "upsecret-123", Probe: probe.Check, ProbeTimeout: time.Second})
	h, err := New(Options{Log: log, Version: "test", Mode: "standalone", DB: d, Edge: svc, Identifier: ident,
		AuthUpstream: netip.MustParseAddrPort("10.0.0.10:1812"), AcctUpstream: netip.MustParseAddrPort("10.0.0.10:1813"),
		CRLWarn: 72 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, db: d, agent: fa, ca: pkitest.NewCA(t, "tenant-a client CA"), serverCA: pkitest.NewCA(t, "server CA")}
}

// client はリダイレクトを追わない（303 を確かめる）。
var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *testEnv) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := client.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// post はフォームを送る（htmx の要求として）。同じオリジンの要求として Sec-Fetch-Site を付ける。
func (e *testEnv) post(t *testing.T, path string, form url.Values) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func must(t *testing.T, what string, status int, body string, wantStatus int, wantText string) {
	t.Helper()
	if status != wantStatus || !strings.Contains(body, wantText) {
		t.Fatalf("%s: status %d (want %d), body does not contain %q:\n%s", what, status, wantStatus, wantText, body)
	}
}

var csrPattern = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----`)

func TestTenantFlow(t *testing.T) {
	e := newTestEnv(t, auth.Dev("op@example.com"))

	s, body := e.get(t, "/")
	must(t, "home", s, body, 200, "ダッシュボード")
	s, body = e.get(t, "/tenants")
	must(t, "tenants", s, body, 200, "10.0.0.10:1812") // 上流の既定がフォームに入る

	// 規則に合わない名前は断る。
	s, body, _ = e.post(t, "/tenants", url.Values{"slug": {"Tenant_A"}, "auth": {"10.0.0.10:1812"}, "acct": {"10.0.0.10:1813"}})
	must(t, "bad slug", s, body, 422, "テナントの名前は")
	s, body, _ = e.post(t, "/tenants", url.Values{"slug": {"tenant-a"}, "auth": {"upstream:1812"}, "acct": {"10.0.0.10:1813"}})
	must(t, "host name", s, body, 422, "ホスト名")
	s, _, hdr := e.post(t, "/tenants", url.Values{"slug": {"tenant-a"}, "auth": {"10.0.0.10:1812"}, "acct": {"10.0.0.10:1813"}})
	if s != 200 || hdr.Get("HX-Redirect") != "/tenants/tenant-a" {
		t.Fatalf("create: %d %v", s, hdr)
	}

	s, body = e.get(t, "/tenants/tenant-a")
	must(t, "detail", s, body, 200, "反映に要るものがそろっていません")
	for _, n := range names.SlotNames("tenant-a", "radsec.test") {
		if !strings.Contains(body, n) {
			t.Errorf("DNS name %s is not shown", n)
		}
	}

	// 証明書と CRL を取り込む。
	s, body, _ = e.post(t, "/tenants/tenant-a/client-ca", url.Values{"pem": {string(e.ca.PEM)}})
	must(t, "client CA", s, body, 200, "クライアントCA の証明書を取り込みました")
	s, body, _ = e.post(t, "/tenants/tenant-a/crl", url.Values{"pem": {string(e.ca.CRL(t, pkitest.CRL{Number: 1}))}})
	must(t, "crl", s, body, 200, "CRL を取り込みました")
	s, body, _ = e.post(t, "/tenants/tenant-a/crl", url.Values{"pem": {"garbage"}})
	must(t, "bad crl", s, body, 422, "CRL を置けません")

	s, body, _ = e.post(t, "/tenants/tenant-a/csr/server", nil)
	must(t, "server csr", s, body, 200, "BEGIN CERTIFICATE REQUEST")
	_, cert := e.serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames("tenant-a", "radsec.test"), Server: true}, []byte(html.UnescapeString(csrPattern.FindString(body))))
	s, body, _ = e.post(t, "/tenants/tenant-a/cert/server", url.Values{"pem": {string(cert)}})
	must(t, "server cert", s, body, 200, "サーバー証明書を取り込みました")

	s, body, _ = e.post(t, "/tenants/tenant-a/csr/probe", nil)
	must(t, "probe csr", s, body, 200, "BEGIN CERTIFICATE REQUEST")
	_, cert = e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", "tenant-a", "probe")}, []byte(html.UnescapeString(csrPattern.FindString(body))))
	s, body, _ = e.post(t, "/tenants/tenant-a/cert/probe", url.Values{"pem": {string(cert)}})
	must(t, "probe cert", s, body, 200, "ヘルスチェック用の証明書を取り込みました")
	if !strings.Contains(body, "radsecproxy.conf の差分") || !strings.Contains(body, "+client tenant-a-probe {") {
		t.Errorf("plan is not shown:\n%s", body)
	}

	// 反映。
	s, body, _ = e.post(t, "/tenants/tenant-a/apply", nil)
	must(t, "apply", s, body, 200, "反映しました")
	if !strings.Contains(body, "反映済みの版と同じです") {
		t.Errorf("plan after apply:\n%s", body)
	}

	// AP の登録と削除。
	s, body, _ = e.post(t, "/tenants/tenant-a/aps", url.Values{"name": {"probe"}})
	must(t, "reserved ap", s, body, 422, "予約")
	s, body, _ = e.post(t, "/tenants/tenant-a/aps", url.Values{"name": {"ap-001"}})
	must(t, "ap", s, body, 200, "tenant-a-ap-001")
	if !strings.Contains(body, "未反映の変更あり") || !strings.Contains(body, "+client tenant-a-ap-001 {") {
		t.Errorf("pending AP is not shown:\n%s", body)
	}
	s, body, _ = e.post(t, "/tenants/tenant-a/aps/ap-001/delete", nil)
	must(t, "ap delete", s, body, 200, "AP ap-001 を削除しました")

	// 設定の変更（ポートの重なりなど）。
	s, body, _ = e.post(t, "/tenants/tenant-a/update", url.Values{"port": {"19999"}, "auth": {"10.0.0.10:1812"}, "acct": {"10.0.0.10:1813"}})
	must(t, "bad port", s, body, 422, "ポートは")
	s, body, _ = e.post(t, "/tenants/tenant-a/update", url.Values{"port": {"20840"}, "auth": {"10.0.0.11:1812"}, "acct": {"10.0.0.11:1813"}})
	must(t, "update", s, body, 200, "テナントの設定を変えました")

	// 運用の操作。
	s, body, _ = e.post(t, "/tenants/tenant-a/restart", nil)
	must(t, "restart", s, body, 200, "再起動しました")
	s, body, _ = e.post(t, "/tenants/tenant-a/stop", nil)
	must(t, "stop", s, body, 200, "停止しました")
	s, body, _ = e.post(t, "/tenants/tenant-a/apply", nil)
	must(t, "apply while stopped", s, body, 422, "停止しているテナントは反映できません")
	s, body, _ = e.post(t, "/tenants/tenant-a/start", nil)
	must(t, "start", s, body, 200, "起動しました")
	s, body = e.get(t, "/tenants/tenant-a/logs")
	must(t, "logs", s, body, 200, "<pre")

	s, body = e.get(t, "/audit")
	must(t, "audit", s, body, 200, "反映")
	if !strings.Contains(body, "op@example.com") {
		t.Errorf("operator is not in the audit log:\n%s", body)
	}
	s, body = e.get(t, "/tenants")
	must(t, "list", s, body, 200, "tenant-a")

	_, _, hdr = e.post(t, "/tenants/tenant-a/delete", nil)
	if hdr.Get("HX-Redirect") != "/tenants" {
		t.Errorf("delete: %v", hdr)
	}
	s, _ = e.get(t, "/tenants/tenant-a")
	if s != 404 {
		t.Errorf("deleted tenant: %d", s)
	}
}

func TestApplyFailureIsShown(t *testing.T) {
	e := newTestEnv(t, auth.Dev("op@example.com"))
	e.post(t, "/tenants", url.Values{"slug": {"tenant-a"}, "auth": {"10.0.0.10:1812"}, "acct": {"10.0.0.10:1813"}})
	s, body, _ := e.post(t, "/tenants/tenant-a/apply", nil)
	must(t, "apply without certificates", s, body, 422, "そろっていません")
	e.agent.FailEnsure = errors.New("boom")
	s, body, _ = e.post(t, "/tenants/tenant-a/restart", nil)
	must(t, "restart without container", s, body, 422, "コンテナがありません")
}

type rejectVerifier struct{ err error }

func (v rejectVerifier) Verify(context.Context, string) (access.Claims, error) {
	return access.Claims{}, v.err
}

func TestAuthentication(t *testing.T) {
	e := newTestEnv(t, auth.Access(rejectVerifier{access.ErrInvalid}))
	s, body := e.get(t, "/")
	must(t, "no token", s, body, 401, "Cloudflare Access")
	// 認証の対象外。
	s, body = e.get(t, "/healthz")
	must(t, "healthz", s, body, 200, "ok")
	s, _ = e.get(t, "/static/htmx.min.js")
	if s != 200 {
		t.Errorf("static: %d", s)
	}
	e = newTestEnv(t, auth.Access(rejectVerifier{access.ErrUnavailable}))
	s, body = e.get(t, "/")
	must(t, "no keys", s, body, 503, "公開鍵")
}

func TestCrossOrigin(t *testing.T) {
	e := newTestEnv(t, auth.Dev("op@example.com"))
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/tenants", strings.NewReader("slug=tenant-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", resp.StatusCode)
	}
	if ts, _ := e.db.Tenants(t.Context()); len(ts) != 0 {
		t.Error("tenant was created by a cross-site request")
	}
	s, _ := e.get(t, "/nosuch")
	if s != 404 {
		t.Errorf("unknown page: %d", s)
	}
}
