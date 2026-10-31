// Package edge はエッジの中心の処理を受け持つ: テナント・AP・証明書の変更、反映（設計概要 §11.1）、
// 整合ループ（§11.5）、CRL の取得と反映（§9.5）。画面と管理API はここを呼ぶ。
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
	"net"
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
	LogsSince(ctx context.Context, id string, since time.Time) (string, error)
	Validate(ctx context.Context, slug, gen string) (agent.ValidateResult, error)
}

// ProbeFunc はヘルスチェックの 1 回の試み（probe.Check と同じ形）。
type ProbeFunc func(ctx context.Context, addr string, cert tls.Certificate, serverCert *x509.Certificate) error

// 刻印の既定（RFC 5612 の文書用の Vendor-Id。実運用では IANA から取得した PEN。§24.2）。
const (
	DefaultStampVendorID   = 32473
	DefaultStampVendorType = 1
)

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
	// Stamp はテナントの刻印の VSA（EDGE_STAMP_VENDOR_ID、EDGE_STAMP_VENDOR_TYPE。ゼロ値なら 32473 と 1。§24.2）。
	Stamp rsconf.Stamp
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
	// ApplyTimeout は裏で動かす反映の上限（0 なら 2 分）。
	ApplyTimeout time.Duration
	// Capacity は 1 台のテナントの数の上限（EDGE_TENANT_CAPACITY。0 なら確かめない。§24.11 の EA12）。
	Capacity int
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

// Service はエッジの中心の処理。
type Service struct {
	Options
	locks sync.Map // テナントの ID → chan struct{}（容量 1）

	mu            sync.Mutex
	lastReconcile ReconcileState

	// bgCtx は裏で動かす反映のコンテキスト（Shutdown で取り消す）。bgWG は裏の反映の終わりを待つ。
	bgCtx    context.Context
	bgCancel context.CancelFunc
	bgWG     sync.WaitGroup
	// applying は裏で動いている反映（テナントの ID → 始めた時刻）。mu で守る。
	applying map[string]time.Time

	// statusCache は agent の状態の写し（EA9）。statusMu で守る。
	statusMu    sync.Mutex
	statusCache agent.Status
	statusAt    time.Time
}

// ReconcileState は最後の整合ループの結果（画面に出す）。
type ReconcileState struct {
	At    time.Time
	Error string
}

// New は Service を作る。
func New(o Options) *Service {
	if o.HTTPClient == nil {
		// 接続は 5 秒で諦める（CA が応答しないときに、テナントの数だけ長く待たないように。§24.11 の EA8）。
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: tr}
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
	if o.Stamp == (rsconf.Stamp{}) {
		o.Stamp = rsconf.Stamp{VendorID: DefaultStampVendorID, VendorType: DefaultStampVendorType}
	}
	if o.ApplyTimeout == 0 {
		o.ApplyTimeout = 2 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{Options: o, bgCtx: ctx, bgCancel: cancel, applying: map[string]time.Time{}}
}

// ErrBusy は、テナントの排他を時間内に取れなかったことを表す（反映などが動いている。§24.11 の EA7）。
var ErrBusy = errors.New("テナントの反映などが動いています。しばらくしてからやり直してください")

type lockWaitKey struct{}

// WithLockWait は、テナントの排他を待つ時間の上限をコンテキストに入れる（管理API の変更の口。§24.11 の EA7）。
// 入れなければ、コンテキストが終わるまで待つ。
func WithLockWait(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, lockWaitKey{}, d)
}

// acquire はテナントの排他を取り、解く関数を返す。取れないまま待つ時間が過ぎるかコンテキストが終わると、ErrBusy を返す。
func (s *Service) acquire(ctx context.Context, id string) (func(), error) {
	m, _ := s.locks.LoadOrStore(id, make(chan struct{}, 1))
	ch := m.(chan struct{})
	release := func() { <-ch }
	select {
	case ch <- struct{}{}:
		return release, nil
	default:
	}
	if d, ok := ctx.Value(lockWaitKey{}).(time.Duration); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	select {
	case ch <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ErrBusy
	}
}

// Actor は操作した人（監査ログと反映の記録に残す）。
type Actor struct {
	// Operator は画面の利用者のメールアドレス（管理API では X-Operator-Id）。MgmtClient は管理API の管理クライアントの識別名。
	Operator   string
	MgmtClient string
	// Source は gui / api / system。
	Source string
	Remote string
}

// System は整合ループと CRL の定期の取得の操作者。
var System = Actor{Operator: "system", Source: db.SourceSystem}

// audit は監査ログを書く。書けなくても操作は失敗にしない（ログに残す）。
func (s *Service) audit(ctx context.Context, a Actor, action, target string, detail map[string]any) {
	err := s.DB.InsertAudit(context.WithoutCancel(ctx), db.AuditEntry{Operator: a.Operator, MgmtClient: a.MgmtClient, Source: a.Source, Action: action,
		Target: target, Detail: detail, TraceID: trace.From(ctx), Remote: a.Remote})
	if err != nil {
		s.Log.Error("cannot write audit log", "action", action, "target", target, "error", err)
	}
	s.Log.Info("audit", "operator", a.Operator, "source", a.Source, "action", action, "target", target, "trace_id", trace.From(ctx))
}

// 誤りの理由の符号（管理API の ProblemDetails の cause に出す。空なら VALIDATION）。
const (
	CauseTenantStopped    = "TENANT_STOPPED"
	CauseNotReady         = "NOT_READY"
	CauseCapacityExceeded = "CAPACITY_EXCEEDED"
	CauseSlugImmutable    = "SLUG_IMMUTABLE"
	CauseConflict         = "CONFLICT"
)

// InputError は利用者の入力の誤り（画面では、そのまま見せる）。Cause は管理API に出す理由の符号。
type InputError struct {
	Msg   string
	Cause string
}

func (e *InputError) Error() string { return e.Msg }

func invalid(format string, args ...any) error { return &InputError{Msg: fmt.Sprintf(format, args...)} }

func invalidCause(cause, format string, args ...any) error {
	return &InputError{Msg: fmt.Sprintf(format, args...), Cause: cause}
}

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
