// Package web はエッジの運用者向けの画面（Go + htmx + daisyUI。設計概要 §13.1）。eapaka-ossbss-sample の画面の土台を
// コピーして手直ししたもの。
//
// 同梱しているサードパーティのファイル（static/）:
//   - htmx.min.js: htmx 2.0.11（https://htmx.org、0BSD）
//   - app.css: Tailwind CSS（MIT）と daisyUI（MIT）で生成する。リポジトリには入れず、scripts/build-css.sh で作る
//     （Docker のビルドの段でも同じスクリプトを使う）。
package web

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/auth"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
)

//go:embed templates static
var assets embed.FS

// Handler は画面のハンドラー。
type Handler struct {
	Options
	pages  pages
	static *staticFiles
}

// Options は Handler の設定。
type Options struct {
	Log *slog.Logger
	// Version は画面のフッターに出すバージョン、Mode はエッジのモード（standalone / managed）。
	Version, Mode string
	DB            *db.DB
	Edge          *edge.Service
	// Identifier は要求から利用者を決める（Cloudflare Access の JWT、または開発用の設定）。
	Identifier auth.Identifier
	// AuthUpstream と AcctUpstream は、テナントを作るときの上流の既定（EDGE_UPSTREAM_AUTH / ACCT）。
	AuthUpstream, AcctUpstream netip.AddrPort
	// CRLWarn は、CRL の nextUpdate までの残りがこれを切ったら警告する値（設計概要 §9.5）。
	CRLWarn time.Duration
	// ApplyTimeout は、画面からの変更の操作（反映など）の上限（0 なら 2 分）。
	ApplyTimeout time.Duration
	// Now は現在時刻（テストで差し替える）。
	Now func() time.Time
}

// New は Handler を作る。テンプレートと静的ファイルはここで読み込む。
func New(o Options) (*Handler, error) {
	if o.Identifier == nil || o.Edge == nil || o.DB == nil {
		return nil, fmt.Errorf("web: identifier, edge and db are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ApplyTimeout == 0 {
		o.ApplyTimeout = 2 * time.Minute
	}
	h := &Handler{Options: o}
	var err error
	if h.pages, err = parsePages(); err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	if h.static, err = newStaticFiles(http.HandlerFunc(h.notFound)); err != nil {
		return nil, fmt.Errorf("load static files: %w", err)
	}
	return h, nil
}

// Routes はルーティングとミドルウェアを組み立てた http.Handler を返す。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", h.static)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /{$}", h.home)

	mux.HandleFunc("GET /tenants", h.tenantList)
	mux.HandleFunc("POST /tenants", h.standaloneOnly(h.tenantCreate))
	mux.HandleFunc("GET /tenants/{id}", h.tenant)
	mux.HandleFunc("POST /tenants/{id}/update", h.standaloneOnly(h.tenantUpdate))
	mux.HandleFunc("POST /tenants/{id}/delete", h.standaloneOnly(h.tenantDelete))
	mux.HandleFunc("POST /tenants/{id}/apply", h.tenantApply)
	mux.HandleFunc("POST /tenants/{id}/restart", h.tenantRestart)
	mux.HandleFunc("POST /tenants/{id}/stop", h.tenantStop)
	mux.HandleFunc("POST /tenants/{id}/start", h.tenantStart)
	mux.HandleFunc("GET /tenants/{id}/logs", h.tenantLogs)
	mux.HandleFunc("POST /tenants/{id}/client-ca", h.standaloneOnly(h.clientCAImport))
	mux.HandleFunc("POST /tenants/{id}/csr/{kind}", h.standaloneOnly(h.csrCreate))
	mux.HandleFunc("POST /tenants/{id}/cert/{kind}", h.standaloneOnly(h.certImport))
	mux.HandleFunc("POST /tenants/{id}/crl", h.standaloneOnly(h.crlUpload))
	mux.HandleFunc("POST /tenants/{id}/crl/refresh", h.crlRefresh)
	mux.HandleFunc("POST /tenants/{id}/aps", h.standaloneOnly(h.apPut))
	mux.HandleFunc("POST /tenants/{id}/aps/{name}/delete", h.standaloneOnly(h.apDelete))

	mux.HandleFunc("GET /audit", h.audit)
	mux.HandleFunc("/", h.notFound)

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Log.Warn("cross-origin request rejected", "method", r.Method, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		h.renderError(w, r, http.StatusForbidden, "この操作は受け付けられません。画面を開き直してから操作してください。")
	}))
	return h.accessLog(securityHeaders(cop.Handler(h.authenticate(mux))))
}

// managed は管理モードか。
func (h *Handler) managed() bool { return h.Mode == config.ModeManaged }

// standaloneOnly は、テナント・AP・証明書・CRL の変更の操作を、管理モードでは断る（設計概要 §23.2 の 3、§24.11 の EA13）。
// 管理モードの望む状態は中央（OSS/BSS）から届く。反映のやり直し・再起動・停止と起動・CRL の取り直し・ログは運用の操作なので使える。
func (h *Handler) standaloneOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.managed() {
			h.renderError(w, r, http.StatusForbidden, "管理モードでは、この変更は中央（OSS/BSS）から行います。")
			return
		}
		next(w, r)
	}
}

// healthz は DB を使えれば 200 を返す（compose の healthcheck に使う。認証の対象外）。
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.DB.Ping(ctx); err != nil {
		h.Log.Warn("healthz: db is not available", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "db is not available")
		return
	}
	fmt.Fprintln(w, "ok")
}

// opContext は、変更の操作に使うコンテキスト。ブラウザが途中で接続を切っても反映などが中途半端に止まらないよう、
// 要求の取り消しからは切り離し、上限の時間だけで切る（トレースID と利用者は引き継ぐ）。
func (h *Handler) opContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), h.ApplyTimeout)
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusNotFound, "ページが見つかりません。")
}
