// Command certgen は、段階 0 の実機の検証に使う CA・証明書・CRL を作る（設計概要 §18）。
// 将来の CA（radsec-ca）と同じく crypto/x509 で作り、radsecproxy（OpenSSL）が受け付けるかも確かめる。
//
//	certgen ca   -cn NAME -out PREFIX                       自己署名の CA（PREFIX.pem / PREFIX.key）
//	certgen leaf -ca PREFIX -cn CN [-dns a,b] [-uri u] -usage server|client -out PREFIX
//	certgen crl  -ca PREFIX [-revoke 16進,16進] [-this -1h] [-next 168h] -number N -out FILE
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "使い方: certgen ca|leaf|crl ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = cmdCA(os.Args[2:])
	case "leaf":
		err = cmdLeaf(os.Args[2:])
	case "crl":
		err = cmdCRL(os.Args[2:])
	default:
		err = fmt.Errorf("不明なサブコマンド: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "certgen:", err)
		os.Exit(1)
	}
}

func cmdCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	cn := fs.String("cn", "", "CN")
	out := fs.String("out", "", "出力の接頭辞")
	days := fs.Int("days", 3650, "有効日数")
	fs.Parse(args)
	if *cn == "" || *out == "" {
		return errors.New("-cn と -out が要る")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: *cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 0, *days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return writeCertKey(*out, der, key)
}

func cmdLeaf(args []string) error {
	fs := flag.NewFlagSet("leaf", flag.ExitOnError)
	caPrefix := fs.String("ca", "", "署名する CA の接頭辞")
	cn := fs.String("cn", "", "CN")
	dns := fs.String("dns", "", "SAN の DNS 名（カンマ区切り）")
	uri := fs.String("uri", "", "SAN の URI")
	usage := fs.String("usage", "", "server か client")
	out := fs.String("out", "", "出力の接頭辞")
	days := fs.Int("days", 365, "有効日数")
	fs.Parse(args)
	if *caPrefix == "" || *cn == "" || *out == "" {
		return errors.New("-ca と -cn と -out が要る")
	}
	caCert, caKey, err := readCA(*caPrefix)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: *cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, *days),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	switch *usage {
	case "server":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return errors.New("-usage は server か client")
	}
	if *dns != "" {
		tmpl.DNSNames = strings.Split(*dns, ",")
	}
	if *uri != "" {
		u, err := url.Parse(*uri)
		if err != nil {
			return err
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeCertKey(*out, der, key); err != nil {
		return err
	}
	// シリアル番号を出す（失効に使う）
	fmt.Printf("%x\n", serial)
	return nil
}

func cmdCRL(args []string) error {
	fs := flag.NewFlagSet("crl", flag.ExitOnError)
	caPrefix := fs.String("ca", "", "CA の接頭辞")
	revoke := fs.String("revoke", "", "失効させるシリアル番号（16進。カンマ区切り）")
	this := fs.Duration("this", -time.Hour, "thisUpdate（今からのずれ）")
	next := fs.Duration("next", 7*24*time.Hour, "nextUpdate（今からのずれ）")
	number := fs.Int64("number", 1, "CRL の番号")
	out := fs.String("out", "", "出力のファイル")
	fs.Parse(args)
	if *caPrefix == "" || *out == "" {
		return errors.New("-ca と -out が要る")
	}
	caCert, caKey, err := readCA(*caPrefix)
	if err != nil {
		return err
	}
	now := time.Now()
	var entries []x509.RevocationListEntry
	if *revoke != "" {
		for _, s := range strings.Split(*revoke, ",") {
			n, ok := new(big.Int).SetString(s, 16)
			if !ok {
				return fmt.Errorf("シリアル番号が読めない: %s", s)
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: now.Add(-time.Minute)})
		}
	}
	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(*number),
		ThisUpdate:                now.Add(*this),
		NextUpdate:                now.Add(*next),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644)
}

// newSerial は 128 ビットの乱数のシリアル番号を作る（設計概要 §9.3）。
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writeCertKey(prefix string, der []byte, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	// radsecproxy を nonroot で動かす試験（V9）のため、鍵も読めるようにしておく（検証用）
	return os.WriteFile(prefix+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o644)
}

func readCA(prefix string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(prefix + ".pem")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(prefix + ".key")
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("PEM が読めない")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("署名に使えない鍵")
	}
	return cert, signer, nil
}
