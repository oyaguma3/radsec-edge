// Package edge はエッジの中心の処理を受け持つ: テナント・AP・証明書の変更、反映（設計概要 §11.1）、
// 整合ループ（§11.5）、CRL の取得と反映（§9.5）。画面（と段階 4 の管理API）はここを呼ぶ。
//
// 同じテナントの反映・CRL の反映・整合・削除は、テナントごとの排他で 1 つずつ行う。
package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/probe"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
	"github.com/oyaguma3/radsec-edge/internal/trace"
)

// Agent は radsec-edge-agent の操作。*agent.Client が満たす。
type Agent interface {
	Status(ctx context.Context) (agent.Status, error)
	Ensure(ctx context.Context, id, slug string, port int) (string, error)
	Restart(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Remove(ctx context.Context, id string) error
	SIGHUP(ctx context.Context, id string) error
	Logs(ctx context.Context, id string, lines int) (string, error)
	Validate(ctx context.Context, slug, gen string) (agent.ValidateResult, error)
}

// ProbeFunc はヘルスチェックの 1 回の試み（probe.Check と同じ形）。
type ProbeFunc func(ctx context.Context, addr string, cert tls.Certificate, serverCert *x509.Certificate) error

// Options は Service の設定。
type Options struct {
	Log   *slog.Logger
	DB    *db.DB
	Agent Agent
	// Store はテナントの radsecproxy の設定のディレクトリ、Keys は鍵の置き場所。
	Store rsconf.Store
	Keys  keystore.Store
	// URNPrefix と DNSDomain は名前の規則の値（EDGE_URN_PREFIX、EDGE_DNS_DOMAIN）。
	URNPrefix, DNSDomain string
	// Secret は上流との共有シークレット（EDGE_UPSTREAM_SECRET）。
	Secret string
	// CRLBaseURL は CRL の配布の口（EDGE_CRL_BASE_URL。空ならテナントごとの取得先だけ）。
	CRLBaseURL string
	// HTTPClient は CRL の取得に使う。nil なら上限 30 秒のクライアント。
	HTTPClient *http.Client
	// ProbeAddr はテナントのヘルスチェックの宛先。nil なら radsecproxy-<slug>:2083（テナントのネットワークの中。§10.2）。
	ProbeAddr func(slug string, port int) string
	// Probe はヘルスチェックの 1 回の試み。nil なら probe.Check。
	Probe ProbeFunc
	// ProbeTimeout は反映の後のヘルスチェックの上限（その間、つながるまで繰り返す）。
	ProbeTimeout time.Duration
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

// Service はエッジの中心の処理。
type Service struct {
	Options
	locks sync.Map // テナントの ID → *sync.Mutex

	mu            sync.Mutex
	lastReconcile ReconcileState
}

// ReconcileState は最後の整合ループの結果（画面に出す）。
type ReconcileState struct {
	At    time.Time
	Error string
}

// New は Service を作る。
func New(o Options) *Service {
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.ProbeAddr == nil {
		o.ProbeAddr = func(slug string, _ int) string { return agent.ContainerName(slug) + ":2083" }
	}
	if o.Probe == nil {
		o.Probe = probe.Check
	}
	if o.ProbeTimeout == 0 {
		o.ProbeTimeout = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{Options: o}
}

// lock はテナントの排他を取り、解く関数を返す。
func (s *Service) lock(id string) func() {
	m, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Actor は操作した人（監査ログと反映の記録に残す）。
type Actor struct {
	// Operator は画面の利用者のメールアドレス（管理API では X-Operator-Id）。
	Operator string
	// Source は gui / api / system。
	Source string
	Remote string
}

// System は整合ループと CRL の定期の取得の操作者。
var System = Actor{Operator: "system", Source: db.SourceSystem}

// audit は監査ログを書く。書けなくても操作は失敗にしない（ログに残す）。
func (s *Service) audit(ctx context.Context, a Actor, action, target string, detail map[string]any) {
	err := s.DB.InsertAudit(context.WithoutCancel(ctx), db.AuditEntry{Operator: a.Operator, Source: a.Source, Action: action,
		Target: target, Detail: detail, TraceID: trace.From(ctx), Remote: a.Remote})
	if err != nil {
		s.Log.Error("cannot write audit log", "action", action, "target", target, "error", err)
	}
	s.Log.Info("audit", "operator", a.Operator, "source", a.Source, "action", action, "target", target, "trace_id", trace.From(ctx))
}

// InputError は利用者の入力の誤り（画面では、そのまま見せる）。
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func invalid(format string, args ...any) error { return &InputError{Msg: fmt.Sprintf(format, args...)} }

// IsInput は利用者の入力の誤りか。
func IsInput(err error) bool {
	_, ok := errors.AsType[*InputError](err)
	return ok
}

// truncate はエラーの文を n バイトまでにする（反映の記録に残すため）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
