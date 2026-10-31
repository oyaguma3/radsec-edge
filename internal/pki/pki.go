// Package pki は、エッジが扱う証明書・CRL・鍵の読み込みと検証、鍵と CSR の作成を行う（設計概要 §9）。
//
// エッジは CA の鍵を持たない。テナントのサーバー証明書とヘルスチェック用の証明書の鍵はエッジで作り、
// CSR を CA に署名させる（鍵はエッジの外に出さない）。取り込む証明書と CRL は、名前と信頼の連鎖をここで確かめる。
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
)

// maxPEMBytes は証明書や鍵の PEM の大きさの上限。MaxCRLBytes は CRL（PEM）の上限で、radsec-ca が受け付ける上限（DER で
// 8 MiB。PEM で約 11 MiB）の CRL を受けられる大きさにする（§24.5）。
const (
	maxPEMBytes = 1 << 20
	MaxCRLBytes = 12 << 20
)

// PEM のブロックの種類。
const (
	blockCert = "CERTIFICATE"
	blockCRL  = "X509 CRL"
	blockKey  = "PRIVATE KEY"
	blockCSR  = "CERTIFICATE REQUEST"
)

// blocks は PEM の中のブロックを順に返す。PEM でない文字が混じっていたら（前後の空白を除いて）エラーにする。
func blocks(data []byte) ([]*pem.Block, error) { return blocksMax(data, maxPEMBytes) }

func blocksMax(data []byte, limit int) ([]*pem.Block, error) {
	if len(data) > limit {
		return nil, errors.New("PEM が大きすぎます")
	}
	var out []*pem.Block
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		b, r := pem.Decode(rest)
		if b == nil {
			return nil, errors.New("PEM として読めません")
		}
		out = append(out, b)
		rest = bytes.TrimSpace(r)
	}
	if len(out) == 0 {
		return nil, errors.New("PEM が空です")
	}
	return out, nil
}

// ParseCert は PEM の証明書を 1 つだけ読む。
func ParseCert(data []byte) (*x509.Certificate, error) {
	bs, err := blocks(data)
	if err != nil {
		return nil, err
	}
	if len(bs) != 1 || bs[0].Type != blockCert {
		return nil, errors.New("PEM の証明書（CERTIFICATE）を 1 つだけ与えてください")
	}
	c, err := x509.ParseCertificate(bs[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("証明書が読めません: %w", err)
	}
	return c, nil
}

// ParseCRL は PEM の CRL を 1 つだけ読む。
func ParseCRL(data []byte) (*x509.RevocationList, error) {
	bs, err := blocksMax(data, MaxCRLBytes)
	if err != nil {
		return nil, err
	}
	if len(bs) != 1 || bs[0].Type != blockCRL {
		return nil, errors.New("PEM の CRL（X509 CRL）を 1 つだけ与えてください")
	}
	c, err := x509.ParseRevocationList(bs[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("CRL が読めません: %w", err)
	}
	return c, nil
}

// ParseKey は PEM の PKCS#8 の秘密鍵を読む。
func ParseKey(data []byte) (crypto.Signer, error) {
	bs, err := blocks(data)
	if err != nil {
		return nil, err
	}
	if len(bs) != 1 || bs[0].Type != blockKey {
		return nil, errors.New("PEM の秘密鍵（PRIVATE KEY）を 1 つだけ与えてください")
	}
	k, err := x509.ParsePKCS8PrivateKey(bs[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("秘密鍵が読めません: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("署名に使えない鍵です")
	}
	return s, nil
}

// EncodeCert と EncodeCRL は DER を PEM にする。
func EncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockCert, Bytes: der})
}
func EncodeCRL(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: blockCRL, Bytes: der}) }

// NewKey は ECDSA P-256 の鍵を作り、PKCS#8 の PEM で返す（設計概要 §9.2）。
func NewKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockKey, Bytes: der}), nil
}

// NewCSR は鍵 keyPEM の CSR（PEM）を作る。CA は CSR の公開鍵だけを使い、Subject と SAN は CA が決めるので
// （radsec-ca の設計概要 §5.3）、ここでは目印の CN だけを入れる。
func NewCSR(keyPEM []byte, cn string) ([]byte, error) {
	k, err := ParseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der}), nil
}

// KeyMatches は、証明書の公開鍵が鍵 keyPEM のものか。
func KeyMatches(cert *x509.Certificate, keyPEM []byte) bool {
	k, err := ParseKey(keyPEM)
	if err != nil {
		return false
	}
	pub, ok := k.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}

// SerialHex はシリアル番号の 16 進（radsec-ca の記録と同じ形）。
func SerialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }

// checkValidity は、証明書が now に有効か。
func checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("証明書はまだ有効になっていません（%s から）", c.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(c.NotAfter) {
		return fmt.Errorf("証明書の期限が切れています（%s まで）", c.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// CheckClientCA は、テナントのクライアントCA の証明書として使えるか（自己署名の CA。設計概要 §9.1）。
func CheckClientCA(ca *x509.Certificate, now time.Time) error {
	if !ca.IsCA || !ca.BasicConstraintsValid {
		return errors.New("CA の証明書ではありません（BasicConstraints の CA がありません）")
	}
	if ca.KeyUsage != 0 && ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("CA の証明書に keyCertSign がありません")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		return errors.New("自己署名の CA の証明書ではありません（テナントのクライアントCA は自己署名。設計概要 §9.1）")
	}
	return checkValidity(ca, now)
}

// IsSelfSigned は証明書が自己署名か（自己署名でない持ち込みの CA には PartialChain が要る。§24.5）。
func IsSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// CheckBroughtCA は、持ち込みの CA の証明書として使えるか（自己署名でなくてよい。§24.3）。CRL を配る CA は cRLSign も求める
// （ないと CRL の署名を確かめられない）。期限は now で確かめる（now がゼロなら確かめない）。
func CheckBroughtCA(ca *x509.Certificate, hasCRL bool, now time.Time) error {
	if !ca.IsCA || !ca.BasicConstraintsValid {
		return errors.New("CA の証明書ではありません（BasicConstraints の CA がありません）")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("CA の証明書に keyCertSign がありません")
	}
	if hasCRL && ca.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("CA の証明書に cRLSign がないので、CRL を確かめられません")
	}
	if now.IsZero() {
		return nil
	}
	return checkValidity(ca, now)
}

// hasEKU は証明書に用途 u があるか。
func hasEKU(c *x509.Certificate, u x509.ExtKeyUsage) bool { return slices.Contains(c.ExtKeyUsage, u) }

// CheckServerCert は、テナントのサーバー証明書として使えるか（serverAuth、3 つのスロットの名前。設計概要 §9.2）。
func CheckServerCert(c *x509.Certificate, keyPEM []byte, slug, domain string, now time.Time) error {
	if c.IsCA {
		return errors.New("CA の証明書はサーバー証明書に使えません")
	}
	if !hasEKU(c, x509.ExtKeyUsageServerAuth) {
		return errors.New("サーバー証明書に serverAuth の用途がありません")
	}
	for _, n := range names.SlotNames(slug, domain) {
		if !slices.Contains(c.DNSNames, n) {
			return fmt.Errorf("サーバー証明書の SAN に %s がありません", n)
		}
	}
	if !KeyMatches(c, keyPEM) {
		return errors.New("サーバー証明書が、エッジで作った鍵のものではありません（CSR を出し直した場合は、新しい CSR で署名した証明書を取り込んでください）")
	}
	return checkValidity(c, now)
}

// CheckClientCert は、テナントのクライアントCA が発行した、SAN の URI が uri のクライアント証明書か
// （AP の証明書とヘルスチェック用の証明書。設計概要 §8.1、§11.3）。
func CheckClientCert(c, ca *x509.Certificate, uri string, now time.Time) error {
	if c.IsCA {
		return errors.New("CA の証明書はクライアント証明書に使えません")
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		return errors.New("テナントのクライアントCA が発行した証明書ではありません")
	}
	if !hasEKU(c, x509.ExtKeyUsageClientAuth) {
		return errors.New("証明書に clientAuth の用途がありません")
	}
	var uris []string
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	if !slices.Contains(uris, uri) {
		return fmt.Errorf("証明書の SAN の URI が %s ではありません（%s）", uri, strings.Join(uris, ", "))
	}
	return checkValidity(c, now)
}

// CRLInfo は検証を通った CRL の値。Number は番号のない CRL なら nil。
type CRLInfo struct {
	Number                 *big.Int
	ThisUpdate, NextUpdate time.Time
	Revoked                int
}

// Previous は今の CRL の番号と時刻（古い CRL に戻さないために比べる）。ゼロ値なら比べない。
type Previous struct {
	Number     *big.Int
	ThisUpdate time.Time
}

// CheckCRLSignature は、CRL が CA の署名で、nextUpdate があることだけを確かめる（束を作るときの、持ち込みの CA の切れた CRL。§24.5）。
func CheckCRLSignature(crl *x509.RevocationList, ca *x509.Certificate) error {
	if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
		return errors.New("CRL の発行者が CA と違います")
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return errors.New("CRL が CA の署名ではありません")
	}
	if crl.NextUpdate.IsZero() {
		return errors.New("CRL に nextUpdate がありません")
	}
	return nil
}

// CheckCRL は、CRL が CA の署名で、nextUpdate が now より後で、今の CRL より古くないことを確かめる（設計概要 §9.5、§11.2）。
// 番号がどちらにもあれば番号で比べ、なければ thisUpdate で比べる（業者の CRL には番号のないものがありうる。§24.5）。
// 期限の切れた CRL を置いて SIGHUP するとその CA の接続が切れるため、期限の切れた CRL は必ず断る。
func CheckCRL(crl *x509.RevocationList, ca *x509.Certificate, prev Previous, now time.Time) (CRLInfo, error) {
	if err := CheckCRLSignature(crl, ca); err != nil {
		return CRLInfo{}, err
	}
	if !now.Before(crl.NextUpdate) {
		return CRLInfo{}, fmt.Errorf("CRL の期限（nextUpdate %s）が切れています", crl.NextUpdate.Format(time.RFC3339))
	}
	switch {
	case prev.Number != nil && crl.Number != nil:
		if crl.Number.Cmp(prev.Number) < 0 {
			return CRLInfo{}, fmt.Errorf("CRL の番号 %s が、今の CRL の番号 %s より小さいです（古い CRL には戻しません）", crl.Number, prev.Number)
		}
	case !prev.ThisUpdate.IsZero() && crl.ThisUpdate.Before(prev.ThisUpdate):
		return CRLInfo{}, fmt.Errorf("CRL の thisUpdate %s が、今の CRL より古いです（古い CRL には戻しません）", crl.ThisUpdate.Format(time.RFC3339))
	}
	return CRLInfo{Number: crl.Number, ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate, Revoked: len(crl.RevokedCertificateEntries)}, nil
}
