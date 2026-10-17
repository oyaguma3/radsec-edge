// Package access は Cloudflare Access が付ける JWT（ヘッダー Cf-Access-Jwt-Assertion）を検証する（設計概要 §13.1）。
// eapaka-ossbss-sample の internal/access をコピーしたもの（共有モジュールにはしない。設計概要 §4）。
//
// 署名は RS256 だけを受け付ける。公開鍵はチームの JWKS（https://<チームのドメイン>/cdn-cgi/access/certs）から
// 取得して覚えておき、1 時間ごとに取り直す。知らない kid が来たら取り直す（鍵の入れ替えに追随する）が、
// 取り直しは 1 分に 1 回までにする（不正な JWT を大量に送られても、Cloudflare への問い合わせが増えないように）。
// 取得できないときは覚えている鍵で検証を続け、覚えている鍵もなければ ErrUnavailable を返す。
package access

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Header は Access が JWT を付けるヘッダー。
const Header = "Cf-Access-Jwt-Assertion"

const (
	// keysTTL は覚えた公開鍵を取り直すまでの時間（JWKS の応答の Cache-Control は 4 時間）。
	keysTTL = time.Hour
	// minRefetchInterval は、知らない kid などで取り直すときの最短の間隔。
	minRefetchInterval = time.Minute
	// emptyRefetchInterval は、公開鍵を 1 つも覚えていない（起動時に取得できなかった）ときの取り直しの最短の間隔。
	emptyRefetchInterval = 5 * time.Second
	// clockSkew は exp / nbf / iat で許す時計のずれ。
	clockSkew = time.Minute
	// fetchTimeout は JWKS の取得の上限時間。
	fetchTimeout = 5 * time.Second
	// maxJWKSBytes は JWKS の応答を読む上限。
	maxJWKSBytes = 1 << 20
	// maxTokenBytes は JWT の長さの上限（Access の JWT は 1KB 程度）。
	maxTokenBytes = 16 << 10
	// minRSABits は受け付ける RSA の鍵の長さの下限。
	minRSABits = 2048
)

var (
	// ErrInvalid は JWT がない・検証できないことを表す（401）。
	ErrInvalid = errors.New("invalid access token")
	// ErrUnavailable は、公開鍵を 1 つも取得できていないため検証できないことを表す（503）。
	ErrUnavailable = errors.New("access public keys are not available")
)

// Options は Verifier の設定。
type Options struct {
	// TeamDomain はチームのドメイン（例 example.cloudflareaccess.com）。iss は https://<TeamDomain>。
	TeamDomain string
	// AUDs は Access のアプリの AUD タグ。JWT の aud にどれかが含まれれば受け付ける。
	AUDs []string
	// CertsURL は JWKS の URL。空なら https://<TeamDomain>/cdn-cgi/access/certs（テストで差し替える）。
	CertsURL string
	// HTTPClient は JWKS の取得に使う。nil なら http.DefaultClient。
	HTTPClient *http.Client
	// Now は現在時刻（テストで差し替える）。nil なら time.Now。
	Now func() time.Time
}

// Claims は検証した JWT の内容のうち、エッジが使うもの。
type Claims struct {
	// Email はログインした利用者のメールアドレス（Access が確かめたもの。小文字にはしていない）。
	Email   string
	Subject string
	Expiry  time.Time
}

// Verifier は JWT を検証する。複数の goroutine から使える。
type Verifier struct {
	issuer   string
	auds     []string
	certsURL string
	client   *http.Client
	now      func() time.Time

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time

	// fetchMu は JWKS の取得を 1 つずつにする。lastAttempt は最後に取得を試みた時刻（fetchMu で守る）。
	fetchMu     sync.Mutex
	lastAttempt time.Time
}

// New は Verifier を作る。公開鍵はまだ取得しない（Refresh か、最初の Verify で取得する）。
func New(opts Options) (*Verifier, error) {
	if opts.TeamDomain == "" || len(opts.AUDs) == 0 {
		return nil, errors.New("access: team domain and AUD are required")
	}
	v := &Verifier{
		issuer:   "https://" + opts.TeamDomain,
		auds:     slices.Clone(opts.AUDs),
		certsURL: cmp.Or(opts.CertsURL, "https://"+opts.TeamDomain+"/cdn-cgi/access/certs"),
		client:   cmp.Or(opts.HTTPClient, http.DefaultClient),
		now:      opts.Now,
		keys:     map[string]*rsa.PublicKey{},
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v, nil
}

// CertsURL は JWKS の URL を返す（起動時のログに使う）。
func (v *Verifier) CertsURL() string { return v.certsURL }

// Refresh は JWKS を取得して公開鍵を入れ替える（起動時に呼ぶ。失敗しても、Verify のときにもう一度試みる）。
// 取得した鍵の数を返す。
func (v *Verifier) Refresh(ctx context.Context) (int, error) {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	return v.fetchLocked(ctx)
}

// Verify は JWT を検証して内容を返す。JWT がない・検証できなければ ErrInvalid を包んだエラー、
// 公開鍵が 1 つもなければ ErrUnavailable を包んだエラーを返す。
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if token == "" {
		return Claims{}, fmt.Errorf("%w: no token", ErrInvalid)
	}
	if len(token) > maxTokenBytes {
		return Claims{}, fmt.Errorf("%w: token is too long", ErrInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: malformed token", ErrInvalid)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return Claims{}, fmt.Errorf("%w: header: %v", ErrInvalid, err)
	}
	// alg は JWT の値を信じて選ばず、RS256 だけを受け付ける（none や HS256 による署名の回避を防ぐ）。
	if hdr.Alg != "RS256" {
		return Claims{}, fmt.Errorf("%w: unsupported alg %q", ErrInvalid, hdr.Alg)
	}
	if hdr.Kid == "" {
		return Claims{}, fmt.Errorf("%w: no kid", ErrInvalid)
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature encoding", ErrInvalid)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, fmt.Errorf("%w: bad signature", ErrInvalid)
	}

	var c struct {
		Iss   string         `json:"iss"`
		Aud   jsontext.Value `json:"aud"`
		Exp   *float64       `json:"exp"`
		Nbf   *float64       `json:"nbf"`
		Iat   *float64       `json:"iat"`
		Email string         `json:"email"`
		Sub   string         `json:"sub"`
	}
	if err := decodeSegment(parts[1], &c); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %v", ErrInvalid, err)
	}
	if c.Iss != v.issuer {
		return Claims{}, fmt.Errorf("%w: unexpected iss %q", ErrInvalid, c.Iss)
	}
	auds, err := audiences(c.Aud)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: aud: %v", ErrInvalid, err)
	}
	if !slices.ContainsFunc(v.auds, func(a string) bool { return slices.Contains(auds, a) }) {
		return Claims{}, fmt.Errorf("%w: unexpected aud", ErrInvalid)
	}
	now := v.now()
	exp := unixTime(c.Exp)
	if exp.IsZero() {
		return Claims{}, fmt.Errorf("%w: no exp", ErrInvalid)
	}
	if !now.Before(exp.Add(clockSkew)) {
		return Claims{}, fmt.Errorf("%w: expired at %s", ErrInvalid, exp.UTC().Format(time.RFC3339))
	}
	if nbf := unixTime(c.Nbf); !nbf.IsZero() && now.Before(nbf.Add(-clockSkew)) {
		return Claims{}, fmt.Errorf("%w: not valid yet", ErrInvalid)
	}
	if iat := unixTime(c.Iat); !iat.IsZero() && iat.After(now.Add(clockSkew)) {
		return Claims{}, fmt.Errorf("%w: issued in the future", ErrInvalid)
	}
	// サービストークンの JWT にはメールアドレスがない（画面の利用者ではない）。
	if strings.TrimSpace(c.Email) == "" {
		return Claims{}, fmt.Errorf("%w: no email", ErrInvalid)
	}
	return Claims{Email: c.Email, Subject: c.Sub, Expiry: exp}, nil
}

// key は kid の公開鍵を返す。覚えていなければ（または古ければ）JWKS を取り直す。
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := v.now().Sub(v.fetchedAt) >= keysTTL
	v.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	// 取り直す（間隔の下限の中なら取り直さない）。失敗しても、覚えている鍵で続ける。
	v.refetch(ctx)
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if len(v.keys) == 0 {
		return nil, ErrUnavailable
	}
	return nil, fmt.Errorf("%w: unknown kid", ErrInvalid)
}

// refetch は、最後の試みから間隔の下限を過ぎていれば JWKS を取り直す。
func (v *Verifier) refetch(ctx context.Context) {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	v.mu.RLock()
	interval := minRefetchInterval
	if len(v.keys) == 0 {
		interval = emptyRefetchInterval
	}
	v.mu.RUnlock()
	if !v.lastAttempt.IsZero() && v.now().Sub(v.lastAttempt) < interval {
		return
	}
	v.fetchLocked(ctx) // 失敗は呼び出し側で「鍵がない」として扱う
}

// fetchLocked は JWKS を取得して公開鍵を入れ替える。fetchMu を持って呼ぶ。
func (v *Verifier) fetchLocked(ctx context.Context) (int, error) {
	v.lastAttempt = v.now()
	// 要求が取り消されても取得は最後まで行う（他の要求も待っているため）。
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	keys, err := v.fetch(ctx)
	if err != nil {
		return 0, err
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, v.now()
	v.mu.Unlock()
	return len(keys), nil
}

// jwks は JWKS の応答（public_cert(s) は使わない）。
type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", v.certsURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", v.certsURL, resp.Status)
	}
	var set jwks
	if err := json.UnmarshalRead(io.LimitReader(resp.Body, maxJWKSBytes), &set); err != nil {
		return nil, fmt.Errorf("fetch %s: decode: %w", v.certsURL, err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("fetch %s: no usable RS256 keys", v.certsURL)
	}
	return keys, nil
}

// rsaKey は JWK の n / e（base64url）から公開鍵を作る。短い鍵は受け付けない。
func rsaKey(n64, e64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("unsupported RSA key")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// audiences は aud（文字列、または文字列の配列）を配列にする。
func audiences(v jsontext.Value) ([]string, error) {
	if len(v) == 0 {
		return nil, errors.New("missing")
	}
	var one string
	if err := json.Unmarshal(v, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(v, &many); err != nil {
		return nil, err
	}
	return many, nil
}

// unixTime は NumericDate（秒。小数を含みうる）を時刻にする。なければゼロ値。
func unixTime(f *float64) time.Time {
	if f == nil {
		return time.Time{}
	}
	return time.Unix(int64(*f), 0)
}
