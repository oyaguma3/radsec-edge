package edge

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// startUpstream は偽の上流（testdata/fakeupstream）をテナントのネットワークで動かし、コンテナの名前と IP アドレスを返す。
func startUpstream(t *testing.T, e *env) (string, netip.Addr) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fakeupstream")
	build := exec.Command("go", "build", "-o", bin, "./testdata/fakeupstream")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var rnd [4]byte
	rand.Read(rnd[:])
	name := "radsec-edge-test-upstream-" + hex.EncodeToString(rnd[:])
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "--network", e.network, "-v", bin+":/fakeupstream:ro", "debian:13.7-slim", "/fakeupstream").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("upstream address %q: %v", out, err)
	}
	return name, ip
}

// keyCert は pkitest の CA で発行した証明書と鍵（AP の役）。
type keyCert struct {
	cert   tls.Certificate
	serial *big.Int
}

func issueTo(t *testing.T, ca *pkitest.CA, l pkitest.Leaf) keyCert {
	t.Helper()
	_, key := pkitest.NewKeyPair(t)
	csr, err := pki.NewCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	c, certPEM := ca.SignCSR(t, l, csr)
	pair, err := tls.X509KeyPair(certPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	return keyCert{cert: pair, serial: c.SerialNumber}
}

// rsConn は RadSec の接続（AP の役）。
type rsConn struct {
	c  *tls.Conn
	id byte
}

func dialRS(port int, kc keyCert) (*rsConn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{Certificates: []tls.Certificate{kc.cert}, InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	return &rsConn{c: c}, nil
}

// request は Access-Request か Accounting-Request を送り、応答を待つ。AP が送る属性として、偽の刻印と別の業者の VSA を付ける。
func (r *rsConn) request(code byte, user, nas string) error {
	const secret = "radsec"
	attr := func(t byte, v []byte) []byte { return append([]byte{t, byte(len(v) + 2)}, v...) }
	vsa := func(vendor uint32, typ byte, v string) []byte {
		b := binary.BigEndian.AppendUint32(nil, vendor)
		b = append(b, typ, byte(len(v)+2))
		return attr(26, append(b, v...))
	}
	var attrs []byte
	attrs = append(attrs, attr(1, []byte(user))...)
	if nas != "" {
		attrs = append(attrs, attr(32, []byte(nas))...)
	}
	attrs = append(attrs, vsa(32473, 1, "999")...)
	attrs = append(attrs, vsa(9, 1, "other")...)
	r.id++
	if code == 4 {
		attrs = append(attrs, attr(40, []byte{0, 0, 0, 1})...) // Acct-Status-Type = Start
		attrs = append(attrs, attr(44, []byte("session-1"))...)
	}
	pkt := append([]byte{code, r.id, 0, 0}, make([]byte, 16)...)
	maAt := -1
	if code == 1 {
		rand.Read(pkt[4:20])
		attrs = append(attrs, 80, 18)
		maAt = 20 + len(attrs)
		attrs = append(attrs, make([]byte, 16)...)
	}
	pkt = append(pkt, attrs...)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	if maAt >= 0 {
		m := hmac.New(md5.New, []byte(secret))
		m.Write(pkt)
		copy(pkt[maAt:maAt+16], m.Sum(nil))
	} else {
		h := md5.New()
		h.Write(pkt)
		h.Write([]byte(secret))
		copy(pkt[4:20], h.Sum(nil))
	}
	r.c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := r.c.Write(pkt); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(r.c, head); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if n < 20 {
		return fmt.Errorf("short reply: %d", n)
	}
	_, err := io.CopyN(io.Discard, r.c, int64(n-4))
	return err
}

func (r *rsConn) close() { r.c.Close() }

// trustEnv は結合の試験の環境。
type trustEnv struct {
	*env
	t        *testing.T
	port     int
	upstream string
	seen     int
}

// roundTrip は新しい接続で要求を 1 つ送る。
func (te *trustEnv) roundTrip(kc keyCert, user, nas string) error {
	c, err := dialRS(te.port, kc)
	if err != nil {
		return err
	}
	defer c.close()
	return c.request(1, user, nas)
}

// accepted は接続が受け入れられることを確かめる。
func (te *trustEnv) accepted(what string, kc keyCert) {
	te.t.Helper()
	var err error
	// statusServer が上流を生きていると判断するまでの間は、要求の応答が遅れることがあるので、少し繰り返す。
	for range 3 {
		if err = te.roundTrip(kc, what, ""); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	te.logsFail(what+": want accepted", err)
}

// rejected は接続が断られることを確かめる。
func (te *trustEnv) rejected(what string, kc keyCert) {
	te.t.Helper()
	if err := te.roundTrip(kc, what, ""); err == nil {
		te.logsFail(what+": want rejected", nil)
	}
}

func (te *trustEnv) logsFail(what string, err error) {
	te.t.Helper()
	logs, _ := te.svc.Agent.Logs(te.t.Context(), "tenant-a", 60)
	_, b, _ := te.svc.Store.Current("tenant-a")
	te.t.Fatalf("%s (%v)\n--- radsecproxy\n%s\n--- conf\n%s", what, err, logs, b[rsconf.FileConf])
}

var reqLine = regexp.MustCompile(`REQ code=(\d+) user=(\S*) nas=(\S*) stamps=(\S*) othervendors=(\d+)`)

// seenAtUpstream は上流が受け取った user の最後の要求（nas と刻印と別の業者の VSA の数）を返す。
func (te *trustEnv) seenAtUpstream(user string) (nas, stamps, others string) {
	te.t.Helper()
	for range 20 {
		out, _ := exec.Command("docker", "logs", te.upstream).CombinedOutput()
		for _, m := range reqLine.FindAllStringSubmatch(string(out), -1) {
			if m[2] == user {
				nas, stamps, others = m[3], m[4], m[5]
			}
		}
		if nas != "" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	te.t.Fatalf("the upstream did not get a request of %s", user)
	return
}

// 本物の radsecproxy で、AP・グループ・持ち込みの CA を混ぜたテナントの受け口を確かめる（設計概要 §24）。
func TestDockerTrust(t *testing.T) {
	e := dockerEnv(t)
	ctx := t.Context()
	name, ip := startUpstream(t, e)
	te := &trustEnv{env: e, t: t, port: 21990, upstream: name}
	e.readyTenant(t, "tenant-a")
	up := func(p uint16) netip.AddrPort { return netip.AddrPortFrom(ip, p) }
	if _, err := e.svc.UpdateTenant(ctx, e.user, "tenant-a", TenantInput{Port: te.port, Auth: up(1812), Acct: up(1813)}); err != nil {
		t.Fatal(err)
	}
	apply := func(what string) {
		t.Helper()
		if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
			logs, _ := e.svc.Agent.Logs(ctx, "tenant-a", 60)
			t.Fatalf("Apply(%s) = %+v, %v\n%s", what, rec, err, logs)
		}
	}

	// AP・グループ・持ち込みの CA（自己署名）を混ぜる。
	ap := issueTo(t, e.ca, pkitest.Leaf{CN: "tenant-a-ap-001", URI: names.SANURI("example", "tenant-a", "ap-001")})
	group := issueTo(t, e.ca, pkitest.Leaf{CN: "tenant-a-unifi", URI: names.GroupSANURI("example", "tenant-a", "unifi")})
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PutGroup(ctx, e.user, "tenant-a", "unifi", "unifi", nil); err != nil {
		t.Fatal(err)
	}
	vendor := pkitest.NewCA(t, "vendor org CA")
	vendorAP := issueTo(t, vendor, pkitest.Leaf{CN: "aabbccddeeff"})
	vendorAP2 := issueTo(t, vendor, pkitest.Leaf{CN: "aabbccddee00"})
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "vendor", vendor, true)}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.vendor", vendor.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	apply("mixed")

	// 刻印と NAS-Identifier。AP が送った偽の刻印は消して付け直し、別の業者の VSA は残す。
	check := func(what, wantNAS string) {
		t.Helper()
		nas, stamps, others := te.seenAtUpstream(what)
		if nas != wantNAS || stamps != "tenant-a" || others != "1" {
			t.Errorf("%s: nas=%s stamps=%s others=%s, want nas=%s stamps=tenant-a others=1", what, nas, stamps, others, wantNAS)
		}
	}
	retry := func(kc keyCert, user, nas string) {
		t.Helper()
		var err error
		for range 3 {
			if err = te.roundTrip(kc, user, nas); err == nil {
				return
			}
			time.Sleep(time.Second)
		}
		te.logsFail(user, err)
	}
	retry(ap, "user-ap", "spoofed")
	check("user-ap", "tenant-a-ap-001") // AP は置き換える
	retry(group, "user-group", "real-ap-7")
	check("user-group", "real-ap-7") // グループはそのまま通す
	retry(group, "user-group-none", "")
	check("user-group-none", "tenant-a-unifi") // 送らなければ補う
	retry(vendorAP, "user-vendor", "meraki-ap-1")
	check("user-vendor", "meraki-ap-1") // 共通のブロックもそのまま通す
	retry(vendorAP, "user-vendor-none", "")
	check("user-vendor-none", "tenant-a") // 送らなければテナントの名前で補う
	// Accounting にも刻印が付く。
	c, err := dialRS(te.port, ap)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.request(4, "user-acct", ""); err != nil {
		te.logsFail("accounting", err)
	}
	c.close()
	check("user-acct", "tenant-a-ap-001")

	// 共通のブロックの接続は送信元の IP ごとに記録する。
	var shared int
	for range 20 {
		if err := e.svc.RefreshLastSeen(ctx); err != nil {
			t.Fatal(err)
		}
		st, _ := e.svc.Agent.Status(ctx)
		ct, _ := st.Container("tenant-a")
		rows, err := e.svc.SharedSeen(ctx, "tenant-a", ct.StartedAt)
		if err != nil {
			t.Fatal(err)
		}
		if shared = len(rows); shared > 0 && !rows[0].LastUp.IsZero() {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if shared == 0 {
		t.Error("no shared_seen row")
	}
	seen, _ := e.db.Seen(ctx, "tenant-a")
	if seen["unifi"].LastUp.IsZero() {
		t.Errorf("group is not seen: %+v", seen)
	}

	// 持ち込みの CA の失効は、その証明書だけに効く。
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.vendor", vendor.CRL(t, pkitest.CRL{Number: 2, Revoked: []*big.Int{vendorAP2.serial}})); err != nil {
		t.Fatal(err)
	}
	te.rejected("revoked vendor AP", vendorAP2)
	te.accepted("vendor AP", vendorAP)
	te.accepted("our AP", ap)

	// 持ち込みの CA の CRL が切れても、こちらの AP は巻き込まれない（aka-mvpset の verify/r11 を生成した設定で確かめる）。
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.vendor",
		vendor.CRL(t, pkitest.CRL{Number: 3, NextUpdate: time.Now().Add(6 * time.Second)})); err != nil {
		t.Fatal(err)
	}
	ownConn, err := dialRS(te.port, ap)
	if err != nil {
		te.logsFail("own connection", err)
	}
	defer ownConn.close()
	if err := ownConn.request(1, "own-before", ""); err != nil {
		te.logsFail("own connection", err)
	}
	vendorConn, err := dialRS(te.port, vendorAP)
	if err != nil {
		te.logsFail("vendor connection", err)
	}
	defer vendorConn.close()
	if err := vendorConn.request(1, "vendor-before", ""); err != nil {
		te.logsFail("vendor connection", err)
	}
	time.Sleep(7 * time.Second)
	te.rejected("new vendor AP after expiry", vendorAP)
	te.accepted("new own AP after expiry", ap)
	if err := vendorConn.request(1, "vendor-existing", ""); err != nil {
		te.logsFail("existing vendor connection before reload", err)
	}
	// 発行した CA の新しい CRL（こちらの失効）は読み込ませる。切れるのは業者の AP の接続だけ。ヘルスチェックも通る。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 2})); err != nil {
		t.Fatalf("issued CRL with an expired brought CRL: %v", err)
	}
	time.Sleep(time.Second)
	if err := ownConn.request(1, "own-after", ""); err != nil {
		te.logsFail("our existing connection was cut by SIGHUP", err)
	}
	if err := vendorConn.request(1, "vendor-after", ""); err == nil {
		te.logsFail("the existing vendor connection survived SIGHUP with an expired CRL", nil)
	}
	te.accepted("new own AP after SIGHUP", ap)
	te.rejected("new vendor AP after SIGHUP", vendorAP)

	// 自己署名でない CA（Meraki の形）は PartialChain で起点にする。同じルートの下の別の組織は拒否する。
	root := pkitest.NewCA(t, "vendor root")
	orgA, orgB := root.NewIntermediate(t, "org A RadSec CA"), root.NewIntermediate(t, "org B RadSec CA")
	merakiA := issueTo(t, orgA, pkitest.Leaf{CN: "Q2AA-AAAA-AAAA"})
	merakiB := issueTo(t, orgB, pkitest.Leaf{CN: "Q2BB-BBBB-BBBB"})
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "meraki", orgA, true)}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.InstallBroughtCRL(ctx, e.user, "tenant-a", "brought.tenant-a.meraki", orgA.CRL(t, pkitest.CRL{Number: 1})); err != nil {
		t.Fatal(err)
	}
	apply("partial chain")
	_, b, _ := e.svc.Store.Current("tenant-a")
	if !bytes.Contains(b[rsconf.FileConf], []byte("PartialChain on")) {
		t.Errorf("no PartialChain:\n%s", b[rsconf.FileConf])
	}
	te.accepted("org A", merakiA)
	te.rejected("org B", merakiB)
	te.accepted("our AP with PartialChain", ap)
	te.rejected("the removed vendor CA", vendorAP)

	// 送信元の範囲。範囲外の AP は断られるが、反映のヘルスチェックは内部のサブネットから通る。
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{SourceCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}); err != nil {
		t.Fatal(err)
	}
	apply("source range")
	te.rejected("outside the source range", ap)
	st, err := e.svc.Agent.Status(ctx)
	if err != nil || len(st.NetworkSubnets) == 0 {
		t.Fatalf("subnets: %v %v", st.NetworkSubnets, err)
	}
	inside := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	for _, n := range st.NetworkSubnets {
		inside = append(inside, netip.MustParsePrefix(n))
	}
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{SourceCIDRs: inside}); err != nil {
		t.Fatal(err)
	}
	apply("source range including the test")
	te.accepted("inside the source range", ap)

	// CRL のない持ち込みの CA。CRLCheck off で、共通のブロックを業者の証明書の形で絞る。
	mist := pkitest.NewCA(t, "mist org CA")
	mistAP := issueTo(t, mist, pkitest.Leaf{CN: "001122334455"})
	mistOdd := issueTo(t, mist, pkitest.Leaf{CN: "not-a-mac"})
	if err := e.svc.SetTrust(ctx, e.user, "tenant-a", TrustInput{Brought: []BroughtInput{brought("tenant-a", "mist", mist, false)},
		SharedMatch: rsconf.Match{Attr: "CN", Pattern: "^[0-9a-f]{12}$"}}); err != nil {
		t.Fatal(err)
	}
	// こちらの AP を失効させてブロックを消す（CRLCheck off では失効は TLS で効かない。絞り込みで共通のブロックにも入らない）。
	if err := e.svc.InstallCRL(ctx, e.user, "tenant-a", e.ca.CRL(t, pkitest.CRL{Number: 3, Revoked: []*big.Int{ap.serial}})); err != nil {
		t.Fatal(err)
	}
	apply("no crl")
	_, b, _ = e.svc.Store.Current("tenant-a")
	if !bytes.Contains(b[rsconf.FileConf], []byte("CRLCheck off")) || bytes.Contains(b[rsconf.FileCABundle], []byte("X509 CRL")) {
		t.Errorf("CRLCheck off:\n%s", b[rsconf.FileConf])
	}
	te.accepted("mist AP", mistAP)
	te.rejected("mist certificate of another form", mistOdd)
	te.accepted("revoked own AP passes with CRLCheck off while its block exists", ap)
	if err := e.svc.DeleteAP(ctx, e.user, "tenant-a", "ap-001"); err != nil {
		t.Fatal(err)
	}
	apply("ap removed")
	te.rejected("own AP after its block is removed", ap)
}
