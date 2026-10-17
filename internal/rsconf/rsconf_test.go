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
		URNPrefix:     "example",
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
	ca, crl, err := b.Trust()
	if err != nil || !ca.Equal(f.ca.Cert) || crl.Number.Int64() != 1 {
		t.Errorf("Trust = %v, %v, %v", ca, crl, err)
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
		"other ca crl": {func(f *fixture, in *Input) { in.CRLPEM = f.serverCA.CRL(t, pkitest.CRL{Number: 1}) }, "署名"},
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
