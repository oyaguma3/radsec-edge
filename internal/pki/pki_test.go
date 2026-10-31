package pki

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

func TestParse(t *testing.T) {
	ca := pkitest.NewCA(t, "a client CA")
	if _, err := ParseCert(ca.PEM); err != nil {
		t.Fatal(err)
	}
	// 2 つの証明書、PEM でないもの、種類の違うものは断る。
	for _, in := range []string{string(ca.PEM) + string(ca.PEM), "garbage", "", string(ca.PEM) + "trailing"} {
		if _, err := ParseCert([]byte(in)); err == nil {
			t.Errorf("ParseCert(%.20q) = nil", in)
		}
	}
	crl := ca.CRL(t, pkitest.CRL{Number: 1})
	if _, err := ParseCert(crl); err == nil {
		t.Error("ParseCert(CRL) = nil")
	}
	if _, err := ParseCRL(crl); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCRL(ca.PEM); err == nil {
		t.Error("ParseCRL(cert) = nil")
	}
}

func TestKeyAndCSR(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, "tenant-a server")
	if err != nil {
		t.Fatal(err)
	}
	ca := pkitest.NewCA(t, "server CA")
	c, _ := ca.SignCSR(t, pkitest.Leaf{CN: "x", Server: true}, csr)
	if !KeyMatches(c, key) {
		t.Error("KeyMatches = false")
	}
	other, _ := NewKey()
	if KeyMatches(c, other) {
		t.Error("KeyMatches(other) = true")
	}
}

func TestCheckServerCert(t *testing.T) {
	now := time.Now()
	ca := pkitest.NewCA(t, "server CA")
	key, _ := NewKey()
	csr, _ := NewCSR(key, "x")
	dns := names.SlotNames("tenant-a", "radsec.test")
	good, _ := ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a server edge1", DNS: dns, Server: true}, csr)
	if err := CheckServerCert(good, key, "tenant-a", "radsec.test", now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		leaf pkitest.Leaf
		want string
	}{
		"client":   {pkitest.Leaf{DNS: dns}, "serverAuth"},
		"wildcard": {pkitest.Leaf{DNS: []string{"*.tenant-a.radsec.test"}, Server: true}, "primary.tenant-a.radsec.test"},
		"two":      {pkitest.Leaf{DNS: dns[:2], Server: true}, "tertiary"},
		"expired":  {pkitest.Leaf{DNS: dns, Server: true, NotAfter: now.Add(-time.Minute)}, "期限"},
	}
	for name, tc := range cases {
		c, _ := ca.SignCSR(t, tc.leaf, csr)
		if err := CheckServerCert(c, key, "tenant-a", "radsec.test", now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other, _ := NewKey()
	if err := CheckServerCert(good, other, "tenant-a", "radsec.test", now); err == nil {
		t.Error("other key accepted")
	}
}

func TestCheckClientCert(t *testing.T) {
	now := time.Now()
	ca := pkitest.NewCA(t, "a client CA")
	other := pkitest.NewCA(t, "b client CA")
	_, keyPEM := pkitest.NewKeyPair(t)
	csr, _ := NewCSR(keyPEM, "x")
	uri := names.SANURI("example", "tenant-a", "ap-001")
	good, _ := ca.SignCSR(t, pkitest.Leaf{URI: uri}, csr)
	if err := CheckClientCert(good, ca.Cert, uri, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckClientCert(good, other.Cert, uri, now); err == nil {
		t.Error("other CA accepted")
	}
	if err := CheckClientCert(good, ca.Cert, names.SANURI("example", "tenant-a", "ap-002"), now); err == nil {
		t.Error("wrong URI accepted")
	}
	srv, _ := ca.SignCSR(t, pkitest.Leaf{URI: uri, Server: true}, csr)
	if err := CheckClientCert(srv, ca.Cert, uri, now); err == nil {
		t.Error("server cert accepted")
	}
	if err := CheckClientCA(ca.Cert, now); err != nil {
		t.Error(err)
	}
	if err := CheckClientCA(good, now); err == nil {
		t.Error("leaf accepted as CA")
	}
}

func TestCheckCRL(t *testing.T) {
	now := time.Now()
	ca := pkitest.NewCA(t, "a client CA")
	other := pkitest.NewCA(t, "b client CA")
	parse := func(p []byte) *x509.RevocationList {
		c, err := ParseCRL(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := parse(ca.CRL(t, pkitest.CRL{Number: 5, Revoked: []*big.Int{big.NewInt(7)}}))
	info, err := CheckCRL(good, ca.Cert, Previous{Number: big.NewInt(5)}, now)
	if err != nil || info.Number.Int64() != 5 || info.Revoked != 1 {
		t.Fatalf("CheckCRL = %+v, %v", info, err)
	}
	if _, err := CheckCRL(good, other.Cert, Previous{}, now); err == nil {
		t.Error("other CA accepted")
	}
	if _, err := CheckCRL(good, ca.Cert, Previous{Number: big.NewInt(6)}, now); err == nil || !strings.Contains(err.Error(), "小さい") {
		t.Errorf("older number: %v", err)
	}
	expired := parse(ca.CRL(t, pkitest.CRL{Number: 6, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)}))
	if _, err := CheckCRL(expired, ca.Cert, Previous{}, now); err == nil || !strings.Contains(err.Error(), "期限") {
		t.Errorf("expired: %v", err)
	}
}

// 番号のない CRL（業者の CRL にありうる）は受け、thisUpdate の後退を断る（設計概要 §24.5）。
func TestCheckCRLWithoutNumber(t *testing.T) {
	ca := pkitest.NewCA(t, "vendor")
	now := time.Now()
	crl, err := ParseCRL(ca.CRL(t, pkitest.CRL{Number: 1, ThisUpdate: now.Add(-time.Hour)}))
	if err != nil {
		t.Fatal(err)
	}
	crl.Number = nil // 署名は RawTBS で確かめるので、読んだ値だけを番号なしにする
	info, err := CheckCRL(crl, ca.Cert, Previous{}, now)
	if err != nil || info.Number != nil {
		t.Fatalf("no number: %+v, %v", info, err)
	}
	if _, err := CheckCRL(crl, ca.Cert, Previous{Number: big.NewInt(9), ThisUpdate: now.Add(-2 * time.Hour)}, now); err != nil {
		t.Errorf("newer thisUpdate: %v", err)
	}
	if _, err := CheckCRL(crl, ca.Cert, Previous{ThisUpdate: now.Add(-time.Minute)}, now); err == nil || !strings.Contains(err.Error(), "古い") {
		t.Errorf("older thisUpdate: %v", err)
	}
	// 今の CRL に番号がなく、新しい CRL に番号があるときも thisUpdate で比べる。
	numbered, _ := ParseCRL(ca.CRL(t, pkitest.CRL{Number: 2, ThisUpdate: now.Add(-3 * time.Hour)}))
	if _, err := CheckCRL(numbered, ca.Cert, Previous{ThisUpdate: now.Add(-time.Hour)}, now); err == nil {
		t.Error("older numbered CRL accepted")
	}
}

func TestCheckBroughtCA(t *testing.T) {
	now := time.Now()
	root := pkitest.NewCA(t, "root")
	mid := root.NewIntermediate(t, "org CA")
	if IsSelfSigned(mid.Cert) || !IsSelfSigned(root.Cert) {
		t.Error("IsSelfSigned")
	}
	if err := CheckBroughtCA(mid.Cert, true, now); err != nil {
		t.Errorf("intermediate: %v", err)
	}
	if err := CheckBroughtCA(mid.Cert, true, now.AddDate(20, 0, 0)); err == nil {
		t.Error("expired accepted")
	}
	if err := CheckBroughtCA(mid.Cert, true, time.Time{}); err != nil {
		t.Errorf("no time: %v", err)
	}
	noCRLSign := *mid.Cert
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	if err := CheckBroughtCA(&noCRLSign, true, now); err == nil || !strings.Contains(err.Error(), "cRLSign") {
		t.Errorf("no cRLSign: %v", err)
	}
	if err := CheckBroughtCA(&noCRLSign, false, now); err != nil {
		t.Errorf("no cRLSign without a CRL: %v", err)
	}
	notCA := *mid.Cert
	notCA.IsCA = false
	if err := CheckBroughtCA(&notCA, false, now); err == nil {
		t.Error("not a CA accepted")
	}
}

// radsec-ca の上限（DER で 8 MiB）の CRL を受けられる大きさにする。証明書は 1 MiB のまま。
func TestSizeLimits(t *testing.T) {
	big1 := bytes.Repeat([]byte("a"), maxPEMBytes+1)
	if _, err := ParseCert(big1); err == nil || !strings.Contains(err.Error(), "大きすぎ") {
		t.Errorf("large cert: %v", err)
	}
	if _, err := ParseCRL(big1); err == nil || strings.Contains(err.Error(), "大きすぎ") {
		t.Errorf("1 MiB CRL hit the limit: %v", err)
	}
	if _, err := ParseCRL(bytes.Repeat([]byte("a"), MaxCRLBytes+1)); err == nil || !strings.Contains(err.Error(), "大きすぎ") {
		t.Errorf("large CRL: %v", err)
	}
	if MaxCRLBytes < 8<<20*4/3+1<<20 {
		t.Errorf("MaxCRLBytes %d is too small for an 8 MiB DER CRL in PEM", MaxCRLBytes)
	}
}
