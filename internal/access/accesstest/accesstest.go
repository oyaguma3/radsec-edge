// Package accesstest は、Cloudflare Access の JWT の検証を試すための部品（テスト用）。
// RSA の鍵を作って JWT に署名し、その公開鍵を JWKS として配る httptest のサーバーを立てる。
package accesstest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TeamDomain はテストのチームのドメイン。AUD はテストの AUD タグ。
const (
	TeamDomain = "test-team.cloudflareaccess.com"
	AUD        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// Issuer は JWT の発行元（Access の代わり）。
type Issuer struct {
	Server *httptest.Server
	// Fetches は JWKS が取得された回数。
	Fetches atomic.Int64

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
	// current は署名に使う鍵の kid。
	current string
	// down なら JWKS の取得に 500 を返す。
	down bool
}

// NewIssuer は鍵を 1 つ作り、JWKS のサーバーを立てる。サーバーはテストの終わりに止まる。
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	is := &Issuer{keys: map[string]*rsa.PrivateKey{}}
	is.Rotate(t)
	is.Server = httptest.NewServer(http.HandlerFunc(is.serveJWKS))
	t.Cleanup(is.Server.Close)
	return is
}

// CertsURL は JWKS の URL。
func (is *Issuer) CertsURL() string { return is.Server.URL + "/cdn-cgi/access/certs" }

// Rotate は新しい鍵を作って署名に使う（古い鍵も JWKS に残す。Access の鍵の入れ替えと同じ）。新しい kid を返す。
func (is *Issuer) Rotate(t testing.TB) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var b [32]byte
	rand.Read(b[:])
	kid := hex.EncodeToString(b[:])
	is.mu.Lock()
	is.keys[kid], is.current = k, kid
	is.mu.Unlock()
	return kid
}

// Drop は kid の鍵を JWKS から外す。
func (is *Issuer) Drop(kid string) {
	is.mu.Lock()
	delete(is.keys, kid)
	is.mu.Unlock()
}

// SetDown は JWKS の取得を失敗させる（true）か、戻す（false）。
func (is *Issuer) SetDown(down bool) {
	is.mu.Lock()
	is.down = down
	is.mu.Unlock()
}

func (is *Issuer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	is.Fetches.Add(1)
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.down {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	type jwk struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		E   string `json:"e"`
		N   string `json:"n"`
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	for kid, k := range is.keys {
		set.Keys = append(set.Keys, jwk{Kid: kid, Kty: "RSA", Alg: "RS256", Use: "sig",
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			N: base64.RawURLEncoding.EncodeToString(k.N.Bytes())})
	}
	w.Header().Set("Content-Type", "application/json")
	json.MarshalWrite(w, set)
}

// Claims は Access の JWT に似せた内容を返す（有効期限は 1 時間後）。
func Claims(email string) map[string]any {
	now := time.Now()
	return map[string]any{
		"aud": []string{AUD}, "email": email, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"iss": "https://" + TeamDomain, "type": "app", "identity_nonce": "nonce", "sub": "sub-" + email, "country": "JP",
	}
}

// Sign は claims を今の鍵で RS256 で署名した JWT を返す。
func (is *Issuer) Sign(t testing.TB, claims map[string]any) string {
	t.Helper()
	is.mu.Lock()
	kid, key := is.current, is.keys[is.current]
	is.mu.Unlock()
	return SignWith(t, key, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}, claims)
}

// SignWith は header と claims を key で RS256 で署名した JWT を返す（header の alg は書いたまま使う）。
func SignWith(t testing.TB, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// CurrentKey は署名に使っている鍵と kid を返す（形の違う JWT を作るテストに使う）。
func (is *Issuer) CurrentKey() (string, *rsa.PrivateKey) {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.current, is.keys[is.current]
}
