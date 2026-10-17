// Package pkitest は、試験で CA の代わりに使う小さな CA（証明書・CRL の発行）を提供する。
// radsec-ca と同じく crypto/x509 で作る（段階 0 の verify/v0 の certgen と同じ作り方）。
package pkitest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// CA は試験用の自己署名の CA。
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// PEM は CA の証明書（PEM）。
	PEM []byte
}

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// NewCA は自己署名の CA を作る。
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Leaf は発行する証明書の中身。
type Leaf struct {
	CN     string
	DNS    []string
	URI    string
	Server bool // true なら serverAuth、false なら clientAuth
	// NotBefore と NotAfter（ゼロ値なら 1 時間前と 1 年後）。
	NotBefore, NotAfter time.Time
}

// Issue は pub の公開鍵に証明書を発行し、証明書と PEM を返す。
func (ca *CA) Issue(t testing.TB, l Leaf, pub crypto.PublicKey) (*x509.Certificate, []byte) {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: l.CN},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     l.DNS,
	}
	if !l.NotBefore.IsZero() {
		tmpl.NotBefore = l.NotBefore
	}
	if !l.NotAfter.IsZero() {
		tmpl.NotAfter = l.NotAfter
	}
	if l.Server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if l.URI != "" {
		u, err := url.Parse(l.URI)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// SignCSR は CSR（PEM）の公開鍵に証明書を発行する（CA と同じく、CSR の Subject と拡張は使わない）。
func (ca *CA) SignCSR(t testing.TB, l Leaf, csrPEM []byte) (*x509.Certificate, []byte) {
	t.Helper()
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		t.Fatal("CSR が PEM ではありません")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return ca.Issue(t, l, csr.PublicKey)
}

// NewKeyPair は ECDSA P-256 の鍵を作り、鍵と PKCS#8 の PEM を返す（AP の役の鍵など）。
func NewKeyPair(t testing.TB) (crypto.Signer, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// CRL は CRL の中身。
type CRL struct {
	Number  int64
	Revoked []*big.Int
	// ThisUpdate と NextUpdate（ゼロ値なら 1 時間前と 7 日後）。
	ThisUpdate, NextUpdate time.Time
}

// CRL は CRL を作り、PEM を返す。
func (ca *CA) CRL(t testing.TB, c CRL) []byte {
	t.Helper()
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(c.Number),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(7 * 24 * time.Hour),
	}
	if !c.ThisUpdate.IsZero() {
		tmpl.ThisUpdate = c.ThisUpdate
	}
	if !c.NextUpdate.IsZero() {
		tmpl.NextUpdate = c.NextUpdate
	}
	for _, s := range c.Revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: now.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
