package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/certs"
)

var (
	clientNamePattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Clients は管理クライアントの一覧。フィンガープリント（SHA-256、16 進小文字）から識別名を引く。
type Clients map[string]string

// ParseClients はピンのファイルの中身を解釈する。1 行に「識別名=フィンガープリント」を書く（aka-vecgen・aka-radius・aka-provisioner
// と同じ形）。# で始まる行と空行は無視する。フィンガープリントは SHA-256 の 16 進で、大文字やコロン区切りも受け付ける。
// 同じ識別名を 2 行以上書ける（証明書の入れ替えの間は新旧の両方を受ける）。同じフィンガープリントが 2 回出たら誤り。
func ParseClients(v string) (Clients, error) {
	clients := Clients{}
	for i, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, fp, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || !clientNamePattern.MatchString(name) {
			return nil, fmt.Errorf("line %d: want <name>=<sha256 fingerprint>", i+1)
		}
		fp = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
		if !fingerprintPattern.MatchString(fp) {
			return nil, fmt.Errorf("line %d: bad fingerprint for %q: want 64 hex digits", i+1, name)
		}
		if other, dup := clients[fp]; dup {
			return nil, fmt.Errorf("line %d: fingerprint of %q is already used by %q", i+1, name, other)
		}
		clients[fp] = name
	}
	return clients, nil
}

// Pins は管理クライアントのピン。ファイルから読み、SIGHUP で読み直す（Reload）。
type Pins struct {
	path string
	mu   sync.Mutex // Reload を 1 つずつにする
	cur  atomic.Pointer[pinSet]
}

type pinSet struct {
	clients  Clients
	loadedAt time.Time
}

// LoadPins は path のピンのファイルを読む。読めない・形が違う・1 つもないときはエラーを返す。
func LoadPins(path string) (*Pins, error) {
	p := &Pins{path: path}
	return p, p.Reload()
}

// NewPins は決まった管理クライアントの Pins を作る（試験用。Reload はできない）。
func NewPins(c Clients) *Pins {
	p := &Pins{}
	p.cur.Store(&pinSet{clients: c, loadedAt: time.Now()})
	return p
}

// Reload はピンのファイルを読み直す。読めない・形が違う・1 つもないときは前のピンのまま続け、エラーを返す。
// 読み直した後のハンドシェイクから新しいピンで照合する（張ってある接続は切らない）。
func (p *Pins) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == "" {
		return errors.New("admin clients file is not set")
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}
	c, err := ParseClients(string(data))
	if err != nil {
		return fmt.Errorf("%s: %w", p.path, err)
	}
	if len(c) == 0 {
		return fmt.Errorf("%s: at least one admin client is required", p.path)
	}
	p.cur.Store(&pinSet{clients: c, loadedAt: time.Now()})
	return nil
}

// Names は管理クライアントの識別名を重ねずに辞書順で返す。
func (p *Pins) Names() []string {
	var out []string
	for _, n := range p.cur.Load().clients {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Fingerprints はピンのフィンガープリントの数を返す（ログ用）。
func (p *Pins) Fingerprints() int { return len(p.cur.Load().clients) }

// lookup はフィンガープリントの識別名を返す（なければ false）。
func (p *Pins) lookup(fp string) (string, bool) {
	n, ok := p.cur.Load().clients[fp]
	return n, ok
}

// NameFromRequest は、要求を送ってきた管理クライアントの識別名を返す。mTLS でない・登録されていなければ空文字列。
func (p *Pins) NameFromRequest(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	n, _ := p.lookup(certs.Fingerprint(r.TLS.PeerCertificates[0]))
	return n
}
