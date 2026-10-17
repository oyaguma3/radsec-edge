package web

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/access"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/trace"
)

// contentSecurityPolicy は画面の CSP。スクリプトとスタイルは同梱のファイルだけを許可する。
// daisyUI はアイコン（チェックボックスの印など）を data: の SVG で埋め込んでいるので、画像は data: も許可する。
// htmx の eval とインラインのスタイル挿入は htmx-config（layout.html）で無効にしている。
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", contentSecurityPolicy)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder はアクセスログのためにステータスコードを記録する。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap は http.ResponseController が元の ResponseWriter を使えるようにする。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// reqInfo は、アクセスログに出すために、後のミドルウェアが書き込む値。
type reqInfo struct {
	email string
}

type reqInfoKey struct{}

// accessLog はリクエストごとにアクセスログを出す。静的ファイルと /healthz は debug レベルにする。
// クエリ文字列は出さない。リクエストごとにトレースID を採番してコンテキストに入れる（監査ログと agent の呼び出しに渡る）。
func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID := trace.New()
		info := &reqInfo{}
		r = r.WithContext(context.WithValue(trace.With(r.Context(), traceID), reqInfoKey{}, info))
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" {
			level = slog.LevelDebug
		}
		h.Log.Log(r.Context(), level, "access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", cmp.Or(rec.status, http.StatusOK),
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", h.Identifier.ClientIP(r),
			"user", info.email,
			"trace_id", traceID,
		)
	})
}

type actorKey struct{}

// actorFrom は認証した利用者を、edge の操作者として返す（authenticate を通った要求だけ）。
func actorFrom(ctx context.Context) edge.Actor {
	a, _ := ctx.Value(actorKey{}).(edge.Actor)
	return a
}

// isPublic は認証の対象外のパス（静的ファイルと /healthz）か。
func isPublic(path string) bool { return strings.HasPrefix(path, "/static/") || path == "/healthz" }

// authenticate は要求の利用者を決めてコンテキストに入れる。JWT がない・検証できなければ 401、公開鍵を使えなければ 503 を返す。
// エッジの画面を使えるのは Cloudflare Access のポリシーで許した運用者だけなので、利用者の表は引かない（設計概要 §7.1）。
func (h *Handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		email, err := h.Identifier.Identify(r)
		switch {
		case errors.Is(err, access.ErrUnavailable):
			h.Log.Error("cannot verify access token: no public keys", "error", err)
			h.renderError(w, r, http.StatusServiceUnavailable,
				"利用者を確かめられません（Cloudflare Access の公開鍵を取得できません）。しばらくしてから開き直してください。")
			return
		case err != nil:
			h.Log.Warn("unauthenticated request", "path", r.URL.Path, "reason", err.Error())
			h.renderError(w, r, http.StatusUnauthorized, "Cloudflare Access を通して開いてください。")
			return
		}
		if info, ok := r.Context().Value(reqInfoKey{}).(*reqInfo); ok {
			info.email = email
		}
		a := edge.Actor{Operator: email, Source: db.SourceGUI, Remote: h.Identifier.ClientIP(r)}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, a)))
	})
}
