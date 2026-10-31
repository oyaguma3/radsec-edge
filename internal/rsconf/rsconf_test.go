package rsconf

import (
	"bytes"
	"flag"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

var update = flag.Bool("update", false, "testdata の期待するファイルを書き直す")

// fixture は試験用のテナントの材料（CA、CRL、サーバー証明書と鍵）。
type fixture struct {
	ca, serverCA *pkitest.CA
	in           Input
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ca := pkitest.NewCA(t, "tenant-a client CA")
	serverCA := pkitest.NewCA(t, "server CA")
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := pki.NewCSR(key, "x")
	_, cert := serverCA.SignCSR(t, pkitest.Leaf{CN: "tenant-a server edge1", DNS: names.SlotNames("tenant-a", "radsec.test"), Server: true}, csr)
	return &fixture{ca: ca, serverCA: serverCA, in: Input{
		Slug:          "tenant-a",
		TenantID:      "42",
		URNPrefix:     "example",
		Stamp:         Stamp{VendorID: 32473, VendorType: 1},
		APs:           []string{"ap-002", "ap-001"},
		Auth:          netip.MustParseAddrPort("10.0.0.10:1812"),
		Acct:          netip.MustParseAddrPort("10.0.0.10:1813"),
		Secret:        "upsecret-123",
		ClientCAPEM:   ca.PEM,
		CRLPEM:        ca.CRL(t, pkitest.CRL{Number: 1}),
		ServerCertPEM: cert,
		ServerKeyPEM:  key,
		Now:           time.Now(),
	}}
}

func TestRenderGolden(t *testing.T) {
	f := newFixture(t)
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "tenant-a.conf")
	if *update {
		if err := os.WriteFile(golden, b[FileConf], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[FileConf], want) {
		t.Errorf("radsecproxy.conf differs from %s (go test -update で書き直す):\n%s", golden, b[FileConf])
	}
	// CA のファイルには CA の証明書と CRL が入る。
	entries, err := b.Trust()
	if err != nil || len(entries) != 1 || !entries[0].CA.Equal(f.ca.Cert) || entries[0].CRL.Number.Int64() != 1 {
		t.Errorf("Trust = %v, %v", entries, err)
	}
	if !bytes.Equal(b[FileServerKey], f.in.ServerKeyPEM) || !bytes.Equal(b[FileServerCert], f.in.ServerCertPEM) {
		t.Error("server files differ")
	}
	// 同じ入力からは同じハッシュになる。
	b2, _ := Render(f.in)
	if b.Hash() != b2.Hash() || len(b.Hash()) != 64 {
		t.Errorf("Hash is not stable: %s %s", b.Hash(), b2.Hash())
	}
}

func TestRenderIPv6(t *testing.T) {
	f := newFixture(t)
	f.in.Auth = netip.MustParseAddrPort("[fd00::10]:1812")
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b[FileConf], []byte("host [fd00::10]\n")) {
		t.Errorf("IPv6 host is not bracketed:\n%s", b[FileConf])
	}
}

func TestRenderRejects(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		mod  func(f *fixture, in *Input)
		want string
	}{
		"bad slug":        {func(_ *fixture, in *Input) { in.Slug = "Tenant" }, "テナントの名前"},
		"injection in ap": {func(_ *fixture, in *Input) { in.APs = []string{"ap}\nclient x {"} }, "AP の名前"},
		"regex in ap":     {func(_ *fixture, in *Input) { in.APs = []string{"ap.*"} }, "AP の名前"},
		"probe ap":        {func(_ *fixture, in *Input) { in.APs = []string{"probe"} }, "予約"},
		"duplicate ap":    {func(_ *fixture, in *Input) { in.APs = []string{"ap-001", "ap-001"} }, "重なって"},
		"bad prefix":      {func(_ *fixture, in *Input) { in.URNPrefix = "a:b" }, "接頭辞"},
		"no upstream":     {func(_ *fixture, in *Input) { in.Acct = netip.AddrPort{} }, "上流"},
		"any upstream":    {func(_ *fixture, in *Input) { in.Auth = netip.MustParseAddrPort("0.0.0.0:1812") }, "上流"},
		"bad secret":      {func(_ *fixture, in *Input) { in.Secret = "a b c d e f" }, "共有シークレット"},
		"no crl":          {func(_ *fixture, in *Input) { in.CRLPEM = nil }, "CRL がありません"},
		"expired crl": {func(f *fixture, in *Input) {
			in.CRLPEM = f.ca.CRL(t, pkitest.CRL{Number: 2, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)})
		}, "期限"},
		"other ca crl": {func(f *fixture, in *Input) { in.CRLPEM = f.serverCA.CRL(t, pkitest.CRL{Number: 1}) }, "発行者"},
		"no ca":        {func(_ *fixture, in *Input) { in.ClientCAPEM = nil }, "クライアントCA"},
		"key mismatch": {func(_ *fixture, in *Input) { in.ServerKeyPEM, _ = pki.NewKey() }, "合いません"},
		"no cert":      {func(_ *fixture, in *Input) { in.ServerCertPEM = nil }, "サーバー証明書"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.mod(f, &f.in)
			_, err := Render(f.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Render = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestActionFrom(t *testing.T) {
	f := newFixture(t)
	old, _ := Render(f.in)
	if got := old.ActionFrom(nil); got != ActionRestart {
		t.Errorf("first = %s", got)
	}
	if got := old.ActionFrom(maps.Clone(old)); got != ActionNone {
		t.Errorf("same = %s", got)
	}
	newer, err := old.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 2}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := newer.ActionFrom(old); got != ActionSIGHUP {
		t.Errorf("crl only = %s", got)
	}
	in := f.in
	in.APs = append(in.APs, "ap-003")
	added, _ := Render(in)
	if got := added.ActionFrom(old); got != ActionRestart {
		t.Errorf("ap added = %s", got)
	}
}

// groupAndBrought は AP・グループ・持ち込みの CA を混ぜたテナントの入力を作る。
func groupAndBrought(t *testing.T, f *fixture) (self, intermediate *pkitest.CA) {
	t.Helper()
	root := pkitest.NewCA(t, "vendor root")
	self, intermediate = pkitest.NewCA(t, "vendor self"), root.NewIntermediate(t, "vendor org CA")
	f.in.Groups = []string{"unifi", "box"}
	f.in.Brought = []BroughtCA{
		{ID: "brought.tenant-a.mist", CertPEM: self.PEM, CRLPEM: self.CRL(t, pkitest.CRL{Number: 3}), HasCRL: true},
		{ID: "brought.tenant-a.meraki", CertPEM: intermediate.PEM, CRLPEM: intermediate.CRL(t, pkitest.CRL{Number: 7}), HasCRL: true},
	}
	return self, intermediate
}

func TestRenderMixedGolden(t *testing.T) {
	f := newFixture(t)
	groupAndBrought(t, f)
	f.in.SourceCIDRs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	f.in.ProbeCIDRs = []netip.Prefix{netip.MustParsePrefix("172.31.83.0/24")}
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "tenant-a-mixed.conf")
	if *update {
		if err := os.WriteFile(golden, b[FileConf], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[FileConf], want) {
		t.Errorf("radsecproxy.conf differs from %s (go test -update で書き直す):\n%s", golden, b[FileConf])
	}
	conf := string(b[FileConf])
	// 共通のブロックは必ず最後のブロック。順は AP、グループ、probe、共通。
	order := []string{"client tenant-a-ap-001 {", "client tenant-a-ap-002 {", "client grp-box {", "client grp-unifi {", "client tenant-a-probe {", "client shared {"}
	last := -1
	for _, o := range order {
		i := strings.Index(conf, o)
		if i <= last {
			t.Errorf("block order: %s at %d (previous %d)", o, i, last)
		}
		last = i
	}
	if !strings.Contains(conf, "PartialChain on") || !strings.Contains(conf, "CRLCheck on") {
		t.Errorf("tls block:\n%s", conf)
	}
	// 束は発行した CA が先頭で、持ち込みの CA は ID の順。
	entries, err := b.Trust()
	if err != nil || len(entries) != 3 {
		t.Fatalf("Trust = %v, %v", entries, err)
	}
	if !entries[0].CA.Equal(f.ca.Cert) || entries[1].CA.Subject.CommonName != "vendor org CA" || entries[2].CA.Subject.CommonName != "vendor self" {
		t.Errorf("order: %v", entries)
	}
	for _, e := range entries {
		if e.CRL == nil {
			t.Errorf("no CRL for %v", e.CA.Subject)
		}
	}
}

func TestRenderFlags(t *testing.T) {
	// 自己署名の持ち込みの CA だけなら PartialChain は要らない。
	f := newFixture(t)
	self := pkitest.NewCA(t, "vendor self")
	f.in.Brought = []BroughtCA{{ID: "brought.tenant-a.mist", CertPEM: self.PEM, CRLPEM: self.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true}}
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b[FileConf])
	if strings.Contains(conf, "PartialChain") || !strings.Contains(conf, "CRLCheck on") || !strings.Contains(conf, "client shared {") {
		t.Errorf("self-signed:\n%s", conf)
	}
	// 持ち込みの CA がなければ共通のブロックはない。
	f = newFixture(t)
	b, _ = Render(f.in)
	if strings.Contains(string(b[FileConf]), "client shared") {
		t.Error("shared block without a brought CA")
	}
	// CRL のない CA があると CRLCheck off で、束に CRL を入れない。照合の形が要る。
	f = newFixture(t)
	none := pkitest.NewCA(t, "vendor none")
	f.in.Brought = []BroughtCA{{ID: "brought.tenant-a.mist", CertPEM: none.PEM}}
	if _, err := Render(f.in); err == nil || !strings.Contains(err.Error(), "照合の形") {
		t.Errorf("no match: %v", err)
	}
	f.in.SharedMatch = Match{Attr: "CN", Pattern: "^[0-9a-f]{12}$"}
	if b, err = Render(f.in); err != nil {
		t.Fatal(err)
	}
	conf = string(b[FileConf])
	if !strings.Contains(conf, "CRLCheck off") || !strings.Contains(conf, "matchCertificateAttribute CN:/^[0-9a-f]{12}$/") {
		t.Errorf("off:\n%s", conf)
	}
	entries, _ := b.Trust()
	if len(entries) != 2 || entries[0].CRL != nil || entries[1].CRL != nil {
		t.Errorf("CRLs in the bundle with CRLCheck off: %v", entries)
	}
	// CRLCheck off の束に CRL を入れようとしても変わらない。
	same, err := b.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 2}), time.Now())
	if err != nil || same.Hash() != b.Hash() {
		t.Errorf("WithCRL with CRLCheck off: %v", err)
	}
	// CRL の取得が止まっていても、CRLCheck off なら発行した CA の CRL を求めない。
	f.in.CRLPEM = f.ca.CRL(t, pkitest.CRL{Number: 2, ThisUpdate: time.Now().Add(-48 * time.Hour), NextUpdate: time.Now().Add(-time.Hour)})
	if _, err := Render(f.in); err != nil {
		t.Errorf("expired CRL with CRLCheck off: %v", err)
	}
}

func TestRenderBroughtRejects(t *testing.T) {
	now := time.Now()
	vendor := pkitest.NewCA(t, "vendor")
	cases := map[string]struct {
		mod  func(f *fixture, in *Input)
		want string
	}{
		"same subject as issued": {func(f *fixture, in *Input) {
			o := pkitest.NewCA(t, "tenant-a client CA")
			in.Brought = []BroughtCA{{ID: "x", CertPEM: o.PEM, CRLPEM: o.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true}}
		}, "Subject"},
		"same subject between brought": {func(f *fixture, in *Input) {
			o := pkitest.NewCA(t, "vendor")
			in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, CRLPEM: vendor.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true},
				{ID: "b", CertPEM: o.PEM, CRLPEM: o.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true}}
		}, "Subject"},
		"no crl": {func(f *fixture, in *Input) { in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, HasCRL: true}} }, "CRL がありません"},
		"crl of another ca": {func(f *fixture, in *Input) {
			in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, CRLPEM: f.ca.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true}}
		}, "発行者"},
		"not a ca": {func(f *fixture, in *Input) {
			_, key := pkitest.NewKeyPair(t)
			csr, _ := pki.NewCSR(key, "x")
			_, leaf := vendor.SignCSR(t, pkitest.Leaf{CN: "leaf"}, csr)
			in.Brought = []BroughtCA{{ID: "a", CertPEM: leaf, HasCRL: false}}
			in.SharedMatch = Match{Attr: "CN", Pattern: "^a$"}
		}, "CA の証明書ではありません"},
		"group probe":     {func(_ *fixture, in *Input) { in.Groups = []string{"probe"} }, "予約"},
		"group injection": {func(_ *fixture, in *Input) { in.Groups = []string{"g}\nclient x {"} }, "グループの名前"},
		"group and ap":    {func(_ *fixture, in *Input) { in.Groups = []string{"ap-001"} }, "重なって"},
		"bad tenant id":   {func(_ *fixture, in *Input) { in.TenantID = "4'2" }, "テナントの ID"},
		"bad stamp":       {func(_ *fixture, in *Input) { in.Stamp.VendorType = 256 }, "刻印"},
		"no probe subnet": {func(_ *fixture, in *Input) { in.SourceCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} }, "サブネット"},
		"too many cidrs": {func(_ *fixture, in *Input) {
			in.ProbeCIDRs = []netip.Prefix{netip.MustParsePrefix("172.31.83.0/24")}
			for range MaxSourceCIDRs + 1 {
				in.SourceCIDRs = append(in.SourceCIDRs, netip.MustParsePrefix("10.0.0.0/8"))
			}
		}, "個まで"},
		"bad match": {func(f *fixture, in *Input) {
			in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, CRLPEM: vendor.CRL(t, pkitest.CRL{Number: 1}), HasCRL: true}}
			in.SharedMatch = Match{Attr: "CN", Pattern: "abc"}
		}, "^ で始めて"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.mod(f, &f.in)
			_, err := Render(f.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Render = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// 持ち込みの CA の切れた CRL は断らない（その CA の AP だけが拒否される）。発行した CA の切れた CRL は断る。
	f := newFixture(t)
	f.in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, CRLPEM: vendor.CRL(t, pkitest.CRL{Number: 1, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)}), HasCRL: true}}
	if _, err := Render(f.in); err != nil {
		t.Errorf("expired CRL of a brought CA: %v", err)
	}
}

func TestCheckMatch(t *testing.T) {
	for _, ok := range []Match{{"CN", "^[0-9a-f]{12}$"}, {"SubjectAltName:URI", "^urn:vendor:[a-z]+$"}, {"SubjectAltName:DNS", "^ap[0-9]+\\.example\\.net$"}, {"CN", "^(a|b)$"}} {
		if err := CheckMatch(ok); err != nil {
			t.Errorf("CheckMatch(%v) = %v", ok, err)
		}
	}
	for _, bad := range []Match{
		{"", "^a$"}, {"Subject", "^a$"}, {"CN", ""}, {"CN", "abc"}, {"CN", "^abc"}, {"CN", "abc$"},
		{"CN", "^a$/\n    rewriteIn x #"}, {"CN", "^a b$"}, {"CN", "^a/b$"}, {"CN", "^a#$"}, {"CN", "^a\"$"}, {"CN", "^\\d+$"}, {"CN", "^(?i)a$"}, {"CN", "^(a$"},
		{"CN", "^" + strings.Repeat("a", 128) + "$"},
	} {
		if err := CheckMatch(bad); err == nil {
			t.Errorf("CheckMatch(%q) = nil", bad)
		}
	}
}

// 複数の CA の束で、CRL は発行者の CA のところだけが入れ替わる。ほかの CA の CRL が切れていても入れ替える（失効の反映を優先する）。
func TestWithCRLMixed(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	vendor := pkitest.NewCA(t, "vendor")
	f.in.Brought = []BroughtCA{{ID: "a", CertPEM: vendor.PEM, CRLPEM: vendor.CRL(t, pkitest.CRL{Number: 1, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)}), HasCRL: true}}
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if exp, err := b.IssuedCRLExpired(now); err != nil || exp {
		t.Errorf("issued expired = %v, %v", exp, err)
	}
	b2, err := b.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 2}), now)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := b2.Trust()
	if entries[0].CRL.Number.Int64() != 2 || entries[1].CRL.Number.Int64() != 1 {
		t.Errorf("after issued CRL: %v %v", entries[0].CRL.Number, entries[1].CRL.Number)
	}
	if b2.ActionFrom(b) != ActionSIGHUP {
		t.Errorf("action = %s", b2.ActionFrom(b))
	}
	b3, err := b2.WithCRL(vendor.CRL(t, pkitest.CRL{Number: 5}), now)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ = b3.Trust()
	if entries[0].CRL.Number.Int64() != 2 || entries[1].CRL.Number.Int64() != 5 {
		t.Errorf("after vendor CRL: %v %v", entries[0].CRL.Number, entries[1].CRL.Number)
	}
	other := pkitest.NewCA(t, "other")
	if _, err := b3.WithCRL(other.CRL(t, pkitest.CRL{Number: 1}), now); err == nil {
		t.Error("CRL of an unknown CA accepted")
	}
	// 発行した CA の CRL が切れていれば分かる。
	exp, err := b3.IssuedCRLExpired(now.Add(30 * 24 * time.Hour))
	if err != nil || !exp {
		t.Errorf("issued expired later = %v, %v", exp, err)
	}
}

func TestWithCRL(t *testing.T) {
	f := newFixture(t)
	f.in.CRLPEM = f.ca.CRL(t, pkitest.CRL{Number: 5})
	b, _ := Render(f.in)
	now := time.Now()
	if _, err := b.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 4}), now); err == nil {
		t.Error("older CRL accepted")
	}
	if _, err := b.WithCRL(f.serverCA.CRL(t, pkitest.CRL{Number: 9}), now); err == nil {
		t.Error("CRL of another CA accepted")
	}
	if _, err := b.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 6, ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(-time.Hour)}), now); err == nil {
		t.Error("expired CRL accepted")
	}
	same, err := b.WithCRL(f.ca.CRL(t, pkitest.CRL{Number: 5}), now)
	if err != nil {
		t.Fatalf("same number: %v", err)
	}
	if !bytes.Equal(same[FileConf], b[FileConf]) {
		t.Error("WithCRL changed the config")
	}
}
