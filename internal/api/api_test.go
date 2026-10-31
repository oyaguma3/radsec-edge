package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/certs"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/edge/edgetest"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

type testEnv struct {
	url      string
	client   *http.Client
	db       *db.DB
	svc      *edge.Service
	agent    *edgetest.FakeAgent
	probe    *edgetest.FakeProbe
	ca       *pkitest.CA
	serverCA *pkitest.CA
	// crls は CA の ID ごとの配布の口の中身（なければ 404）。
	mu   sync.Mutex
	crls map[string][]byte
	dial func(cert *tls.Certificate) error
}

func keyPair(t *testing.T, name string, hosts []string) tls.Certificate {
	t.Helper()
	c, k, err := certs.SelfSigned(name, hosts, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func newTestEnv(t *testing.T) *testEnv {
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
	e := &testEnv{db: d, agent: edgetest.NewFakeAgent(), probe: &edgetest.FakeProbe{}, ca: pkitest.NewCA(t, "tenant-a client CA"), serverCA: pkitest.NewCA(t, "server CA"),
		crls: map[string][]byte{}}
	dist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		b, ok := e.crls[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/crl/"), ".pem")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(dist.Close)
	e.svc = edge.New(edge.Options{Log: log, DB: d, Agent: e.agent, Store: rsconf.Store{Root: t.TempDir()}, Keys: keystore.Store{Dir: t.TempDir()},
		URNPrefix: "example", DNSDomain: "radsec.test", Secret: "upsecret-123", CRLBaseURL: dist.URL, Probe: e.probe.Check, ProbeTimeout: time.Second, Capacity: 2})
	t.Cleanup(func() { e.svc.Shutdown(5 * time.Second) })
	srvCert := keyPair(t, "radsec-edge", []string{"127.0.0.1"})
	clientCert := keyPair(t, "provisioner", nil)
	pins := NewPins(Clients{certs.Fingerprint(clientCert.Leaf): "provisioner"})
	h := &Handler{Log: log, DB: d, Edge: e.svc, Version: "test", Mode: "managed", CRLWarn: 72 * time.Hour, MgmtClient: pins.NameFromRequest, AdminClients: pins.Names, LockWait: 100 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(t.Context(), ln, ListenOptions{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil }, Pins: pins, Handler: h.Routes(), Log: log})
	pool := x509.NewCertPool()
	pool.AddCert(srvCert.Leaf)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientCert}}}
	t.Cleanup(tr.CloseIdleConnections)
	addr := ln.Addr().String()
	e.url = "https://" + addr
	e.client = &http.Client{Transport: tr, Timeout: 10 * time.Second}
	e.dial = func(cert *tls.Certificate) error {
		cfg := &tls.Config{RootCAs: pool}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := c.Get("https://" + addr + "/status")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	return e
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
	raw    []byte
}

func (e *testEnv) do(t *testing.T, method, path string, body any, hdr map[string]string) resp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body, json.Deterministic(true))
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.url+path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	out := resp{status: r.StatusCode, header: r.Header, raw: raw}
	json.Unmarshal(raw, &out.body)
	return out
}

var keySeq struct {
	sync.Mutex
	n int
}

// idem は毎回新しい Idempotency-Key のヘッダーを返す。
func idem() map[string]string {
	keySeq.Lock()
	defer keySeq.Unlock()
	keySeq.n++
	return map[string]string{"Idempotency-Key": "k" + strconv.Itoa(keySeq.n), "X-Operator-Id": "admin@example.com"}
}

func expect(t *testing.T, what string, r resp, status int, cause string) {
	t.Helper()
	if r.status != status || (cause != "" && r.body["cause"] != cause) {
		t.Fatalf("%s: status %d cause %v (want %d %s): %s", what, r.status, r.body["cause"], status, cause, r.raw)
	}
	if status >= 400 && r.header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("%s: Content-Type = %s", what, r.header.Get("Content-Type"))
	}
}

func decl(e *testEnv, revision int64, slug string, port int, aps ...map[string]any) map[string]any {
	if aps == nil {
		aps = []map[string]any{}
	}
	return map[string]any{"revision": revision, "slug": slug, "port": port, "authUpstream": "10.0.0.10:1812", "acctUpstream": "10.0.0.10:1813",
		"clientCas": []map[string]any{{"id": "tenant." + slug, "kind": "issued", "certificate": string(e.ca.PEM), "hasCrl": true}}, "aps": aps}
}

// ready はテナントを宣言し、CRL を配布の口に置き、サーバー証明書とヘルスチェック用の証明書を置く。
func (e *testEnv) ready(t *testing.T, id, slug string, port int) {
	t.Helper()
	expect(t, "put", e.do(t, "PUT", "/tenants/"+id, decl(e, 1, slug, port), idem()), 201, "")
	e.mu.Lock()
	e.crls["tenant."+slug] = e.ca.CRL(t, pkitest.CRL{Number: 1})
	e.mu.Unlock()
	r := e.do(t, "POST", "/tenants/"+id+"/server-csr", nil, idem())
	expect(t, "server-csr", r, 200, "")
	_, cert := e.serverCA.SignCSR(t, pkitest.Leaf{DNS: names.SlotNames(slug, "radsec.test"), Server: true}, []byte(r.body["csr"].(string)))
	expect(t, "server-cert", e.do(t, "PUT", "/tenants/"+id+"/server-cert", map[string]string{"certificate": string(cert)}, idem()), 200, "")
	r = e.do(t, "POST", "/tenants/"+id+"/probe-csr", nil, idem())
	expect(t, "probe-csr", r, 200, "")
	_, cert = e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", slug, "probe")}, []byte(r.body["csr"].(string)))
	expect(t, "probe-cert", e.do(t, "PUT", "/tenants/"+id+"/probe-cert", map[string]string{"certificate": string(cert)}, idem()), 200, "")
}

// waitApplied は裏の反映が終わるまで待ち、テナントを返す。
func (e *testEnv) waitApplied(t *testing.T, id string) map[string]any {
	t.Helper()
	for range 200 {
		r := e.do(t, "GET", "/tenants/"+id, nil, nil)
		expect(t, "get", r, 200, "")
		if a := r.body["apply"].(map[string]any); a["state"] == "idle" && a["lastResult"] != nil {
			return r.body
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("apply did not finish")
	return nil
}

func TestMTLS(t *testing.T) {
	e := newTestEnv(t)
	if err := e.dial(nil); err == nil {
		t.Error("a connection without a client certificate was accepted")
	}
	other := keyPair(t, "other", nil)
	if err := e.dial(&other); err == nil {
		t.Error("an unknown client certificate was accepted")
	}
	r := e.do(t, "GET", "/status", nil, map[string]string{"X-Trace-ID": "trace-1"})
	expect(t, "status", r, 200, "")
	if r.header.Get("X-Trace-ID") != "trace-1" || r.body["service"] != "radsec-edge" || r.body["mode"] != "managed" {
		t.Errorf("status: %s", r.raw)
	}
	if c := r.body["capacity"].(map[string]any); c["max"] != float64(2) || c["free"] != float64(2) {
		t.Errorf("capacity = %v", c)
	}
	if _, ok := r.body["tunnel"]; ok {
		t.Error("tunnel is reported")
	}
	if ac := r.body["adminClients"].([]any); len(ac) != 1 || ac[0] != "provisioner" {
		t.Errorf("adminClients = %v", ac)
	}
	if st := r.body["stamp"].(map[string]any); st["vendorId"] != float64(32473) || st["vendorType"] != float64(1) {
		t.Errorf("stamp = %v", st)
	}
	expect(t, "unknown path", e.do(t, "GET", "/nope", nil, nil), 404, "")
	m := e.do(t, "POST", "/status", nil, nil)
	expect(t, "wrong method", m, 405, "")
	if m.header.Get("Allow") == "" {
		t.Error("no Allow header")
	}
	expect(t, "bad operator", e.do(t, "GET", "/status", nil, map[string]string{"X-Operator-Id": "a b"}), 400, "VALIDATION")
}

func TestIdempotency(t *testing.T) {
	e := newTestEnv(t)
	body := decl(e, 1, "tenant-a", 20001)
	expect(t, "no key", e.do(t, "PUT", "/tenants/1", body, nil), 400, "VALIDATION")
	hdr := idem()
	expect(t, "first", e.do(t, "PUT", "/tenants/1", body, hdr), 201, "")
	r := e.do(t, "PUT", "/tenants/1", body, hdr)
	expect(t, "replay", r, 201, "")
	if r.header.Get("Idempotent-Replayed") != "true" {
		t.Error("not replayed")
	}
	expect(t, "other body", e.do(t, "PUT", "/tenants/1", decl(e, 2, "tenant-a", 20001), hdr), 409, "IDEMPOTENCY_CONFLICT")
}

func TestDeclare(t *testing.T) {
	e := newTestEnv(t)
	expect(t, "bad id", e.do(t, "PUT", "/tenants/tenant-a", decl(e, 1, "tenant-a", 20001), idem()), 422, "VALIDATION")
	expect(t, "zero revision", e.do(t, "PUT", "/tenants/1", decl(e, 0, "tenant-a", 20001), idem()), 422, "VALIDATION")
	bad := decl(e, 1, "tenant-a", 20001)
	bad["unknown"] = 1
	expect(t, "unknown member", e.do(t, "PUT", "/tenants/1", bad, idem()), 400, "VALIDATION")
	noIssued := decl(e, 1, "tenant-a", 20001)
	noIssued["clientCas"] = []map[string]any{}
	expect(t, "no issued ca", e.do(t, "PUT", "/tenants/1", noIssued, idem()), 400, "VALIDATION")
	wrongID := decl(e, 1, "tenant-a", 20001)
	wrongID["clientCas"] = []map[string]any{{"id": "tenant.other", "kind": "issued", "certificate": string(e.ca.PEM), "hasCrl": true}}
	expect(t, "wrong ca id", e.do(t, "PUT", "/tenants/1", wrongID, idem()), 422, "VALIDATION")

	aps := []map[string]any{{"name": "ap-001", "kind": "ap", "certSerial": "ab", "certNotAfter": "2030-01-01T00:00:00Z"}, {"name": "hq", "kind": "group", "purpose": "unifi"}}
	r := e.do(t, "PUT", "/tenants/1", decl(e, 3, "tenant-a", 20001, aps...), idem())
	expect(t, "create", r, 201, "")
	if r.body["revision"] != float64(3) || r.body["appliedRevision"] != float64(0) || r.body["pending"] != true || r.body["apCount"] != float64(2) {
		t.Errorf("created: %s", r.raw)
	}
	if m := r.body["missing"].([]any); len(m) != 3 {
		t.Errorf("missing = %v", m)
	}
	cas := r.body["clientCas"].([]any)
	if len(cas) != 1 || cas[0].(map[string]any)["id"] != "tenant.tenant-a" || cas[0].(map[string]any)["kind"] != "issued" {
		t.Errorf("clientCas = %v", cas)
	}
	if list := r.body["aps"].([]any); len(list) != 2 || list[0].(map[string]any)["nasId"] != "tenant-a-ap-001" {
		t.Errorf("aps = %v", list)
	}
	t0, _ := e.db.Tenant(t.Context(), "1")

	// 版だけの違い・表示だけの違いでは内部の版を上げない（EA3）。古い版でも断らない。
	aps[0]["certSerial"] = "cd"
	r = e.do(t, "PUT", "/tenants/1", decl(e, 2, "tenant-a", 20001, aps...), idem())
	expect(t, "same", r, 200, "")
	t1, _ := e.db.Tenant(t.Context(), "1")
	if t1.DesiredVersion != t0.DesiredVersion || t1.Revision != 2 {
		t.Errorf("after the same declaration: desired %d -> %d, revision %d", t0.DesiredVersion, t1.DesiredVersion, t1.Revision)
	}
	if list := r.body["aps"].([]any); list[0].(map[string]any)["certSerial"] != "cd" {
		t.Errorf("display value is not updated: %v", list)
	}
	// AP を減らすと設定が変わる。
	r = e.do(t, "PUT", "/tenants/1", decl(e, 4, "tenant-a", 20001, aps[0]), idem())
	expect(t, "fewer aps", r, 200, "")
	t2, _ := e.db.Tenant(t.Context(), "1")
	if t2.DesiredVersion != t0.DesiredVersion+1 || r.body["apCount"] != float64(1) {
		t.Errorf("after removing an ap: desired %d -> %d, %s", t0.DesiredVersion, t2.DesiredVersion, r.raw)
	}

	expect(t, "slug", e.do(t, "PUT", "/tenants/1", decl(e, 5, "tenant-b", 20001), idem()), 409, "SLUG_IMMUTABLE")
	expect(t, "port in use", e.do(t, "PUT", "/tenants/2", decl(e, 1, "tenant-b", 20001), idem()), 409, "CONFLICT")
	dup := []map[string]any{{"name": "x", "kind": "ap"}, {"name": "x", "kind": "group", "purpose": "box"}}
	expect(t, "dup name", e.do(t, "PUT", "/tenants/1", decl(e, 5, "tenant-a", 20001, dup...), idem()), 422, "VALIDATION")
	expect(t, "group purpose", e.do(t, "PUT", "/tenants/1", decl(e, 5, "tenant-a", 20001, map[string]any{"name": "x", "kind": "group", "purpose": "nope"}), idem()), 422, "VALIDATION")
	expect(t, "tenant b", e.do(t, "PUT", "/tenants/2", decl(e, 1, "tenant-b", 20002), idem()), 201, "")
	expect(t, "capacity", e.do(t, "PUT", "/tenants/3", decl(e, 1, "tenant-c", 20003), idem()), 409, "CAPACITY_EXCEEDED")

	list := e.do(t, "GET", "/tenants", nil, nil)
	expect(t, "list", list, 200, "")
	items := list.body["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["id"] != "1" {
		t.Errorf("items = %v", items)
	}
	if _, has := items[0].(map[string]any)["clientCas"]; has {
		t.Error("the summary has the CA certificates")
	}
	expect(t, "delete", e.do(t, "DELETE", "/tenants/2", nil, idem()), 204, "")
	expect(t, "get deleted", e.do(t, "GET", "/tenants/2", nil, nil), 404, "TENANT_NOT_FOUND")
	expect(t, "delete again", e.do(t, "DELETE", "/tenants/2", nil, idem()), 404, "TENANT_NOT_FOUND")

	// 監査ログに操作者と管理クライアントが残る。
	es, err := e.db.ListAudit(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range es {
		if a.Action == "tenant.declare" && a.Operator == "admin@example.com" && a.MgmtClient == "provisioner" && a.Source == db.SourceAPI && a.TraceID != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit entry for tenant.declare: %+v", es)
	}
}

func TestApplyFlow(t *testing.T) {
	e := newTestEnv(t)
	expect(t, "no tenant", e.do(t, "POST", "/tenants/1/apply", nil, idem()), 404, "TENANT_NOT_FOUND")
	expect(t, "put", e.do(t, "PUT", "/tenants/1", decl(e, 1, "tenant-a", 20001), idem()), 201, "")
	expect(t, "not ready", e.do(t, "POST", "/tenants/1/apply", nil, idem()), 422, "NOT_READY")
	expect(t, "delete", e.do(t, "DELETE", "/tenants/1", nil, idem()), 204, "")
	e.ready(t, "1", "tenant-a", 20001)

	// 足りない CRL は裏の処理の最初に取りに行く。
	r := e.do(t, "POST", "/tenants/1/apply", nil, idem())
	expect(t, "apply", r, 202, "")
	if r.body["state"] != "running" {
		t.Errorf("apply: %s", r.raw)
	}
	got := e.waitApplied(t, "1")
	a := got["apply"].(map[string]any)
	if a["lastResult"] != "ok" || got["appliedRevision"] != float64(1) || got["pending"] != false || got["configHash"] == "" {
		t.Errorf("after apply: %v", got)
	}
	if crls := got["crls"].([]any); len(crls) != 1 || crls[0].(map[string]any)["ok"] != true || crls[0].(map[string]any)["number"] != "1" {
		t.Errorf("crls = %v", crls)
	}
	if got["container"].(map[string]any)["running"] != true {
		t.Errorf("container = %v", got["container"])
	}

	// 証明書の更新は版が変わらないので pending で分かる（EA3）。
	r = e.do(t, "POST", "/tenants/1/probe-csr", nil, idem())
	_, cert := e.ca.SignCSR(t, pkitest.Leaf{URI: names.SANURI("example", "tenant-a", "probe")}, []byte(r.body["csr"].(string)))
	r = e.do(t, "PUT", "/tenants/1/probe-cert", map[string]string{"certificate": string(cert)}, idem())
	expect(t, "probe cert", r, 200, "")
	if r.body["pending"] != true || r.body["revision"] != r.body["appliedRevision"] {
		t.Errorf("after the certificate update: %v", r.body)
	}

	// 宣言の版を上げて反映すると appliedRevision が追いつく。
	expect(t, "put 2", e.do(t, "PUT", "/tenants/1", decl(e, 7, "tenant-a", 20001, map[string]any{"name": "ap-001", "kind": "ap"}), idem()), 200, "")
	expect(t, "apply 2", e.do(t, "POST", "/tenants/1/apply", nil, idem()), 202, "")
	for range 200 {
		got = e.do(t, "GET", "/tenants/1", nil, nil).body
		if got["appliedRevision"] == float64(7) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got["appliedRevision"] != float64(7) || got["pending"] != false {
		t.Errorf("after apply 2: %v", got)
	}

	// 運用の操作。
	expect(t, "restart", e.do(t, "POST", "/tenants/1/restart", nil, idem()), 204, "")
	e.mu.Lock()
	e.crls["tenant.tenant-a"] = e.ca.CRL(t, pkitest.CRL{Number: 2})
	e.mu.Unlock()
	r = e.do(t, "POST", "/tenants/1/crl:refresh", nil, idem())
	expect(t, "crl refresh", r, 200, "")
	if items := r.body["items"].([]any); r.body["ok"] != true || items[0].(map[string]any)["number"] != "2" {
		t.Errorf("crl refresh: %s", r.raw)
	}
	e.mu.Lock()
	delete(e.crls, "tenant.tenant-a")
	e.mu.Unlock()
	r = e.do(t, "POST", "/tenants/1/crl:refresh", nil, idem())
	expect(t, "crl refresh fails", r, 200, "")
	if items := r.body["items"].([]any); r.body["ok"] != false || items[0].(map[string]any)["lastError"] == "" {
		t.Errorf("crl refresh failure: %s", r.raw)
	}
	expect(t, "logs", e.do(t, "GET", "/tenants/1/logs?lines=10", nil, nil), 200, "")
	expect(t, "bad lines", e.do(t, "GET", "/tenants/1/logs?lines=1001", nil, nil), 400, "VALIDATION")
	seen := e.do(t, "GET", "/tenants/1/last-seen", nil, nil)
	expect(t, "last seen", seen, 200, "")
	if aps := seen.body["aps"].([]any); len(aps) != 1 || aps[0].(map[string]any)["name"] != "ap-001" {
		t.Errorf("last-seen: %s", seen.raw)
	}

	// 停止しているテナントは反映も再起動もできない。
	if err := e.svc.SetEnabled(t.Context(), edge.System, "1", false); err != nil {
		t.Fatal(err)
	}
	expect(t, "apply stopped", e.do(t, "POST", "/tenants/1/apply", nil, idem()), 422, "TENANT_STOPPED")
	expect(t, "restart stopped", e.do(t, "POST", "/tenants/1/restart", nil, idem()), 422, "TENANT_STOPPED")
	if got := e.do(t, "GET", "/tenants/1", nil, nil); got.body["enabled"] != false {
		t.Errorf("enabled = %v", got.body["enabled"])
	}
}

func TestBusyAndBackground(t *testing.T) {
	e := newTestEnv(t)
	e.ready(t, "1", "tenant-a", 20001)
	release := make(chan struct{})
	entered := make(chan struct{}, 10)
	inner := e.probe.Check
	e.svc.Probe = func(ctx context.Context, addr string, c tls.Certificate, s *x509.Certificate) error {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return inner(ctx, addr, c, s)
	}
	e.svc.ProbeTimeout = 10 * time.Second
	r := e.do(t, "POST", "/tenants/1/apply", nil, idem())
	expect(t, "apply", r, 202, "")
	if r.body["started"] != true {
		t.Errorf("apply: %s", r.raw)
	}
	<-entered

	// 実行中の再要求は重ねない。読み出しの口は待たない。
	r = e.do(t, "POST", "/tenants/1/apply", nil, idem())
	expect(t, "apply again", r, 202, "")
	if r.body["started"] != false {
		t.Errorf("apply again: %s", r.raw)
	}
	got := e.do(t, "GET", "/tenants/1", nil, nil)
	expect(t, "get", got, 200, "")
	if got.body["apply"].(map[string]any)["state"] != "running" {
		t.Errorf("apply state: %s", got.raw)
	}
	expect(t, "list", e.do(t, "GET", "/tenants", nil, nil), 200, "")

	// 変更の口は短く待って 503。5xx は覚えないので、同じ鍵でやり直せる。
	hdr := idem()
	body := decl(e, 2, "tenant-a", 20001)
	busy := e.do(t, "PUT", "/tenants/1", body, hdr)
	expect(t, "put while applying", busy, 503, "TENANT_BUSY")
	if busy.header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	expect(t, "restart while applying", e.do(t, "POST", "/tenants/1/restart", nil, idem()), 503, "TENANT_BUSY")
	expect(t, "crl while applying", e.do(t, "POST", "/tenants/1/crl:refresh", nil, idem()), 503, "TENANT_BUSY")

	close(release)
	got2 := e.waitApplied(t, "1")
	if got2["apply"].(map[string]any)["lastResult"] != "ok" {
		t.Errorf("after release: %v", got2)
	}
	expect(t, "retry with the same key", e.do(t, "PUT", "/tenants/1", body, hdr), 200, "")
}
