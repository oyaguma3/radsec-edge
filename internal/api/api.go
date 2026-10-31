// Package api はエッジの管理API（9447、mTLS。設計概要 §12.1、§24.11）。呼び出し側は aka-provisioner だけで、全権として扱う。
// 項目の詳しい定めは docs/openapi/edge-api.yaml。radsec-ca の internal/api と同じ作り。
package api

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/trace"
)

const (
	// maxBodyBytes は要求の本文の上限（aka-provisioner の中継の上限と同じ）。
	maxBodyBytes = 1 << 20
	// idempotencyTTL は応答を覚えておく時間、idempotencyPendingTTL は処理中の記録の有効期限。
	idempotencyTTL        = 24 * time.Hour
	idempotencyPendingTTL = time.Minute

	operatorHeader           = "X-Operator-Id"
	idempotencyKeyHeader     = "Idempotency-Key"
	idempotentReplayedHeader = "Idempotent-Replayed"

	// defaultLockWait は変更の口がテナントの排他を待つ時間の上限（§24.11 の EA7）。
	defaultLockWait = 5 * time.Second
	// opTimeout は同期の変更の口の上限（中継のタイムアウトより短くする）。
	opTimeout = 25 * time.Second
)

var (
	// operatorPattern は X-Operator-Id の形式（PoC セットの他の部品と同じ）。
	operatorPattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	// idempotencyKeyPattern は Idempotency-Key の形式（印字可能 ASCII 1〜128 文字）。
	idempotencyKeyPattern = regexp.MustCompile(`^[\x21-\x7E]{1,128}$`)
)

// Handler は管理API のハンドラー。
type Handler struct {
	Log  *slog.Logger
	DB   *db.DB
	Edge *edge.Service
	// MgmtClient は要求から管理クライアントの識別名を取り出す。AdminClients は /status に出す管理クライアントの名前。
	MgmtClient   func(*http.Request) string
	AdminClients func() []string
	// Version と Mode は /status に出す値。
	Version, Mode string
	// CRLWarn は、CRL の nextUpdate までの残りがこれを切ったら警告する値。
	CRLWarn time.Duration
	// LockWait は変更の口がテナントの排他を待つ時間の上限（0 なら 5 秒）。
	LockWait time.Duration
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Route は API の口（OpenAPI と突き合わせる試験に使う）。
type Route struct {
	Method, Path string
	handler      func(*Handler) http.HandlerFunc
	idempotent   bool
}

// Routes は API の口の一覧（§24.11 の EA10）。変更の口は Idempotency-Key が必須（EA11）。
var Routes = []Route{
	{"GET", "/status", func(h *Handler) http.HandlerFunc { return h.status }, false},
	{"GET", "/tenants", func(h *Handler) http.HandlerFunc { return h.listTenants }, false},
	{"GET", "/tenants/{tenantId}", func(h *Handler) http.HandlerFunc { return h.getTenant }, false},
	{"PUT", "/tenants/{tenantId}", func(h *Handler) http.HandlerFunc { return h.putTenant }, true},
	{"DELETE", "/tenants/{tenantId}", func(h *Handler) http.HandlerFunc { return h.deleteTenant }, true},
	{"POST", "/tenants/{tenantId}/server-csr", func(h *Handler) http.HandlerFunc { return h.csr(keystore.Server) }, true},
	{"PUT", "/tenants/{tenantId}/server-cert", func(h *Handler) http.HandlerFunc { return h.putCert(keystore.Server) }, true},
	{"POST", "/tenants/{tenantId}/probe-csr", func(h *Handler) http.HandlerFunc { return h.csr(keystore.Probe) }, true},
	{"PUT", "/tenants/{tenantId}/probe-cert", func(h *Handler) http.HandlerFunc { return h.putCert(keystore.Probe) }, true},
	{"POST", "/tenants/{tenantId}/apply", func(h *Handler) http.HandlerFunc { return h.apply }, true},
	{"POST", "/tenants/{tenantId}/crl:refresh", func(h *Handler) http.HandlerFunc { return h.refreshCRL }, true},
	{"POST", "/tenants/{tenantId}/restart", func(h *Handler) http.HandlerFunc { return h.restart }, true},
	{"GET", "/tenants/{tenantId}/logs", func(h *Handler) http.HandlerFunc { return h.logs }, false},
	{"GET", "/tenants/{tenantId}/last-seen", func(h *Handler) http.HandlerFunc { return h.lastSeen }, false},
}

// Routes はルーティングとミドルウェアを組み立てた http.Handler を返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range Routes {
		hf := rt.handler(h)
		if rt.idempotent {
			hf = h.idempotent(hf)
		}
		mux.HandleFunc(rt.Method+" "+rt.Path, hf)
	}
	return h.observe(checkOperator(withFallback(mux)))
}

// ---- ミドルウェア ----

type ctxKey int

const (
	keyMgmtClient ctxKey = iota
	keyOperator
)

// actor は要求の操作者（監査ログに残す）。
func actor(r *http.Request) edge.Actor {
	mc, _ := r.Context().Value(keyMgmtClient).(string)
	op, _ := r.Context().Value(keyOperator).(string)
	srcIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		srcIP = r.RemoteAddr
	}
	return edge.Actor{Operator: op, MgmtClient: mc, Source: db.SourceAPI, Remote: srcIP}
}

// observe は X-Trace-ID のトレースID を使い（なければ採番し）、コンテキストと応答のヘッダーに入れる。管理クライアントの
// 識別名もコンテキストに入れる。処理を終えた要求は request completed として記録する。
func (h *Handler) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get(trace.Header)
		if !trace.Valid(id) {
			id = trace.New()
		}
		w.Header().Set(trace.Header, id)
		mc := ""
		if h.MgmtClient != nil {
			mc = h.MgmtClient(r)
		}
		r = r.WithContext(edge.WithLockWait(context.WithValue(trace.With(r.Context(), id), keyMgmtClient, mc), cmp.Or(h.LockWait, defaultLockWait)))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		operator := r.Header.Get(operatorHeader)
		if !operatorPattern.MatchString(operator) {
			operator = ""
		}
		srcIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			srcIP = r.RemoteAddr
		}
		h.Log.Info("request completed", "trace_id", id, "method", r.Method, "path", r.URL.Path, "http_status", rec.status,
			"latency_ms", time.Since(start).Milliseconds(), "mgmt_client", mc, "operator", operator, "src_ip", srcIP)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// checkOperator は X-Operator-Id の形式を確かめ、コンテキストに入れる（省略できる）。
func checkOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get(operatorHeader)
		if v != "" && !operatorPattern.MatchString(v) {
			badRequest(operatorHeader, "must match "+operatorPattern.String()).write(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyOperator, v)))
	})
}

// withFallback は、該当しないパスを 404、メソッドを 405 の ProblemDetails で返す（aka-provisioner と同じ）。
func withFallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		var allow []string
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, pattern := mux.Handler(probe); pattern != "" {
				allow = append(allow, m)
			}
		}
		if len(allow) == 0 {
			newProblem(http.StatusNotFound, "", "").write(w)
			return
		}
		if slices.Contains(allow, http.MethodGet) {
			allow = append(allow, http.MethodHead)
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		newProblem(http.StatusMethodNotAllowed, "", "").write(w)
	})
}

// ---- 冪等 ----

// captureWriter は応答を書きながら覚える。
type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

// idempotent は変更の要求の Idempotency-Key を扱う。キーは必須。同じ管理クライアントから同じキー・同じ内容で届いた要求には
// 最初の応答をそのまま返し、内容が違えば 409 IDEMPOTENCY_CONFLICT を返す。覚えるのは 4xx までで、5xx は覚えずに同じキーで
// やり直せるようにする。
func (h *Handler) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(idempotencyKeyHeader)
		if !idempotencyKeyPattern.MatchString(key) {
			badRequest(idempotencyKeyHeader, "required; printable ASCII of 1 to 128 characters").write(w)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			badRequest("body", "request body is too large or could not be read").write(w)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mc := actor(r).MgmtClient
		sum := sha256.New()
		io.WriteString(sum, r.Method+" "+r.URL.Path+"\n")
		sum.Write(body)
		hash := hex.EncodeToString(sum.Sum(nil))
		state, stored, err := h.DB.BeginIdempotent(r.Context(), mc, key, hash, idempotencyPendingTTL)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		switch state {
		case db.IdempotencyInProgress:
			newProblem(http.StatusConflict, causeIdempotencyConflict, "a request with the same Idempotency-Key is in progress").write(w)
			return
		case db.IdempotencyMismatch:
			newProblem(http.StatusConflict, causeIdempotencyConflict, "the Idempotency-Key was used for a different request").write(w)
			return
		case db.IdempotencyReplay:
			if stored.ContentType != "" {
				w.Header().Set("Content-Type", stored.ContentType)
			}
			w.Header().Set(idempotentReplayedHeader, "true")
			w.WriteHeader(stored.Status)
			w.Write(stored.Body)
			return
		}
		rec := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if rec.status >= 500 {
			err = h.DB.AbandonIdempotent(ctx, mc, key, hash)
		} else {
			err = h.DB.CompleteIdempotent(ctx, mc, key, hash, db.StoredResponse{Status: rec.status, ContentType: rec.Header().Get("Content-Type"), Body: rec.buf.Bytes()}, idempotencyTTL)
		}
		if err != nil {
			h.Log.ErrorContext(r.Context(), "cannot record idempotency", "error", err)
		}
	}
}

// readJSON は要求の本文を読む（知らない項目は断る）。
func readJSON(r *http.Request, v any) *problem {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(b) > maxBodyBytes {
		return badRequest("body", "request body is too large or could not be read")
	}
	if err := json.Unmarshal(b, v, json.RejectUnknownMembers(true)); err != nil {
		if se, ok := errors.AsType[*json.SemanticError](err); ok && se.JSONPointer != "" {
			return badRequest(strings.TrimPrefix(string(se.JSONPointer), "/"), "invalid value or unknown member")
		}
		return badRequest("body", "request body must be a JSON object: "+err.Error())
	}
	return nil
}
