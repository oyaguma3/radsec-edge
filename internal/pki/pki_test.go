package pki

import (
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
	info, err := CheckCRL(good, ca.Cert, big.NewInt(5), now)
	if err != nil || info.Number.Int64() != 5 || info.Revoked != 1 {
		t.Fatalf("CheckCRL = %+v, %v", info, err)
	}
	if _, err := CheckCRL(good, other.Cert, nil, now); err == nil {
		t.Error("other CA accepted")
	}
	if _, err := CheckCRL(good, ca.Cert, big.NewInt(6), now); err == nil || !strings.Contains(err.Error(), "小さい") {
		t.Errorf("older number: %v", err)
	}
	expired := parse(ca.CRL(t, pkitest.CRL{Number: 6, ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Hour)}))
	if _, err := CheckCRL(expired, ca.Cert, nil, now); err == nil || !strings.Contains(err.Error(), "期限") {
		t.Errorf("expired: %v", err)
	}
}
