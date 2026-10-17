package access

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/access/accesstest"
)

// clock はテストで進める時計。
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newVerifier(t *testing.T, is *accesstest.Issuer, clk *clock) *Verifier {
	t.Helper()
	v, err := New(Options{TeamDomain: accesstest.TeamDomain, AUDs: []string{"other-app", accesstest.AUD}, CertsURL: is.CertsURL(), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerify(t *testing.T) {
	is := accesstest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	v := newVerifier(t, is, clk)
	if n, err := v.Refresh(t.Context()); err != nil || n != 1 {
		t.Fatalf("refresh = %d, %v", n, err)
	}

	c, err := v.Verify(t.Context(), is.Sign(t, accesstest.Claims("Alice@Example.com")))
	if err != nil || c.Email != "Alice@Example.com" || c.Subject != "sub-Alice@Example.com" || c.Expiry.IsZero() {
		t.Fatalf("verify = %+v, %v", c, err)
	}
	// aud は文字列でもよい。
	claims := accesstest.Claims("a@example.com")
	claims["aud"] = accesstest.AUD
	if _, err := v.Verify(t.Context(), is.Sign(t, claims)); err != nil {
		t.Errorf("aud string: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	is := accesstest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	v := newVerifier(t, is, clk)
	kid, key := is.CurrentKey()
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	with := func(mod func(map[string]any)) string {
		c := accesstest.Claims("a@example.com")
		mod(c)
		return is.Sign(t, c)
	}
	now := time.Now()
	valid := is.Sign(t, accesstest.Claims("a@example.com"))
	parts := strings.Split(valid, ".")

	for name, token := range map[string]string{
		"empty":           "",
		"not a jwt":       "abc",
		"bad base64":      "!!.!!.!!",
		"alg none":        accesstest.SignWith(t, key, map[string]any{"alg": "none", "kid": kid}, accesstest.Claims("a@example.com")),
		"alg HS256":       accesstest.SignWith(t, key, map[string]any{"alg": "HS256", "kid": kid}, accesstest.Claims("a@example.com")),
		"no kid":          accesstest.SignWith(t, key, map[string]any{"alg": "RS256"}, accesstest.Claims("a@example.com")),
		"other key":       accesstest.SignWith(t, other, map[string]any{"alg": "RS256", "kid": kid}, accesstest.Claims("a@example.com")),
		"tampered claims": parts[0] + "." + strings.Split(with(func(c map[string]any) { c["email"] = "evil@example.com" }), ".")[1] + "." + parts[2],
		"no signature":    parts[0] + "." + parts[1] + ".",
		"wrong iss":       with(func(c map[string]any) { c["iss"] = "https://evil.cloudflareaccess.com" }),
		"wrong aud":       with(func(c map[string]any) { c["aud"] = []string{"someone-else"} }),
		"no aud":          with(func(c map[string]any) { delete(c, "aud") }),
		"expired":         with(func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() }),
		"no exp":          with(func(c map[string]any) { delete(c, "exp") }),
		"not yet valid":   with(func(c map[string]any) { c["nbf"] = now.Add(2 * time.Minute).Unix() }),
		"issued later":    with(func(c map[string]any) { c["iat"] = now.Add(2 * time.Minute).Unix() }),
		"service token":   with(func(c map[string]any) { delete(c, "email"); c["common_name"] = "client-id.access" }),
		"blank email":     with(func(c map[string]any) { c["email"] = " " }),
		"too long":        strings.Repeat("a", 20000),
	} {
		if _, err := v.Verify(t.Context(), token); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	// 時計のずれは 1 分まで許す。
	if _, err := v.Verify(t.Context(), with(func(c map[string]any) { c["exp"] = now.Add(-30 * time.Second).Unix() })); err != nil {
		t.Errorf("exp within skew: %v", err)
	}
	if _, err := v.Verify(t.Context(), with(func(c map[string]any) { c["nbf"] = now.Add(30 * time.Second).Unix() })); err != nil {
		t.Errorf("nbf within skew: %v", err)
	}
}

// 鍵の入れ替え: 知らない kid が来たら取り直す。ただし 1 分に 1 回まで。
func TestKeyRotation(t *testing.T) {
	is := accesstest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	v := newVerifier(t, is, clk)
	if _, err := v.Verify(t.Context(), is.Sign(t, accesstest.Claims("a@example.com"))); err != nil {
		t.Fatal(err) // 最初の Verify で取得する
	}
	if n := is.Fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d", n)
	}

	// 1 分以内に入れ替わった鍵は、まだ取り直さない（知らない kid として断る）。
	clk.Add(10 * time.Second)
	old := is.Sign(t, accesstest.Claims("a@example.com"))
	is.Rotate(t)
	rotated := is.Sign(t, accesstest.Claims("a@example.com"))
	if _, err := v.Verify(t.Context(), rotated); !errors.Is(err, ErrInvalid) || is.Fetches.Load() != 1 {
		t.Errorf("rotated within interval: %v, fetches %d", err, is.Fetches.Load())
	}
	// 1 分を過ぎれば取り直して受け付ける。古い鍵の JWT も JWKS にある間は受け付ける。
	clk.Add(time.Minute)
	if _, err := v.Verify(t.Context(), rotated); err != nil || is.Fetches.Load() != 2 {
		t.Errorf("rotated: %v, fetches %d", err, is.Fetches.Load())
	}
	if _, err := v.Verify(t.Context(), old); err != nil {
		t.Errorf("old key: %v", err)
	}
	// 知らない kid を大量に送られても、取り直しは 1 分に 1 回まで。
	_, key := is.CurrentKey()
	forged := accesstest.SignWith(t, key, map[string]any{"alg": "RS256", "kid": "unknown"}, accesstest.Claims("a@example.com"))
	for range 10 {
		v.Verify(t.Context(), forged)
	}
	if n := is.Fetches.Load(); n != 2 {
		t.Errorf("fetches after unknown kids = %d", n)
	}
}

// JWKS を取得できないとき: 覚えている鍵で続ける。覚えている鍵がなければ ErrUnavailable。
func TestJWKSUnavailable(t *testing.T) {
	is := accesstest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	token := is.Sign(t, accesstest.Claims("a@example.com"))

	is.SetDown(true)
	v := newVerifier(t, is, clk)
	if _, err := v.Refresh(t.Context()); err == nil {
		t.Error("refresh while down succeeded")
	}
	if _, err := v.Verify(t.Context(), token); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no keys: %v", err)
	}
	// 鍵がない間の取り直しは 5 秒に 1 回まで。
	fetches := is.Fetches.Load()
	v.Verify(t.Context(), token)
	if is.Fetches.Load() != fetches {
		t.Error("refetched within 5 seconds")
	}
	is.SetDown(false)
	clk.Add(6 * time.Second)
	if _, err := v.Verify(t.Context(), token); err != nil {
		t.Errorf("recovered: %v", err)
	}

	// 鍵を覚えた後に JWKS が落ちても、古くなった鍵で検証を続ける。
	is.SetDown(true)
	clk.Add(2 * time.Hour)
	later := accesstest.Claims("a@example.com")
	later["iat"], later["nbf"], later["exp"] = clk.Now().Unix(), clk.Now().Unix(), clk.Now().Add(time.Hour).Unix()
	if _, err := v.Verify(t.Context(), is.Sign(t, later)); err != nil {
		t.Errorf("stale keys while down: %v", err)
	}
}

// 1 時間たったら取り直し、JWKS から外れた鍵は使わない。
func TestKeysExpire(t *testing.T) {
	is := accesstest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	v := newVerifier(t, is, clk)
	oldKid, _ := is.CurrentKey()
	old := is.Sign(t, accesstest.Claims("a@example.com"))
	if _, err := v.Verify(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	is.Rotate(t)
	is.Drop(oldKid)
	clk.Add(time.Hour)
	later := accesstest.Claims("a@example.com")
	later["iat"], later["nbf"], later["exp"] = clk.Now().Unix(), clk.Now().Unix(), clk.Now().Add(time.Hour).Unix()
	if _, err := v.Verify(t.Context(), is.Sign(t, later)); err != nil {
		t.Errorf("new key: %v", err)
	}
	// 外れた鍵の JWT は、期限内でも受け付けない。
	if _, err := v.Verify(t.Context(), old); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "unknown kid") {
		t.Errorf("dropped key: %v", err)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(Options{TeamDomain: accesstest.TeamDomain}); err == nil {
		t.Error("no aud")
	}
	v, err := New(Options{TeamDomain: "steep-term-c7da.cloudflareaccess.com", AUDs: []string{"x"}})
	if err != nil || v.CertsURL() != "https://steep-term-c7da.cloudflareaccess.com/cdn-cgi/access/certs" {
		t.Errorf("certs url = %q, %v", v.CertsURL(), err)
	}
}
