package web

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/diff"
)

// pages はページごとのテンプレート（layout.html と部品に、ページのファイルを重ねたもの）。
type pages map[string]*template.Template

var funcs = template.FuncMap{
	// asset は静的ファイルの URL（内容のハッシュつき）。
	"asset": assetURL,
	// datetime は日時を表示する（ゼロ値は「-」）。
	"datetime": datetime,
	// short はハッシュなどの先頭 n 文字。
	"short": func(n int, s string) string {
		if len(s) <= n {
			return s
		}
		return s[:n]
	},
	// dict は「名前, 値, …」から部品に渡すマップを作る。
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				m[k] = kv[i+1]
			}
		}
		return m
	},
	// 反映の記録のきっかけ・操作・結果の名前。
	"triggerLabel": triggerLabel,
	"actionLabel":  actionLabel,
	"resultLabel":  resultLabel,
	// auditLabel は監査ログの操作の名前。
	"auditLabel": auditLabel,
	// stateLabel はコンテナの状態の名前。
	"stateLabel": stateLabel,
	// opChar は差分の行の記号。
	"opChar": func(op diff.Op) string { return string(rune(op)) },
}

func parsePages() (pages, error) {
	base, err := template.New("layout.html").Funcs(funcs).Option("missingkey=zero").ParseFS(assets, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	files, err := fs.Glob(assets, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	p := pages{}
	for _, file := range files {
		t, err := template.Must(base.Clone()).ParseFS(assets, file)
		if err != nil {
			return nil, err
		}
		p[strings.TrimSuffix(path.Base(file), ".html")] = t
	}
	return p, nil
}

// datetime は日時をローカルの時刻（TZ）で表示する。
func datetime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// pageData はレイアウトに渡す値。
type pageData struct {
	Title   string
	Version string
	Mode    string
	// User は利用者のメールアドレス（401 などの画面では空）。
	User string
	// Dev は開発用の設定で動いているか。
	Dev bool
	// LogoutURL はログアウトのリンク（Cloudflare Access のログアウト。開発用の設定では空）。
	LogoutURL string
	// Section はナビゲーションで強調する項目（パスの最初の要素）。
	Section string
	Nav     []navItem
	Data    any
}

// navItem はナビゲーションの 1 項目。
type navItem struct {
	Label, Href string
	// Sections は、この項目を強調するパスの最初の要素。
	Sections []string
}

// Active は、section の画面でこの項目を強調するか。
func (n navItem) Active(section string) bool { return slices.Contains(n.Sections, section) }

var nav = []navItem{
	{"ダッシュボード", "/", []string{""}},
	{"テナント", "/tenants", []string{"tenants"}},
	{"監査ログ", "/audit", []string{"audit"}},
}

// accessLogoutURL は Cloudflare Access のログアウト（公開ホスト名のパス。Access が処理する）。
const accessLogoutURL = "/cdn-cgi/access/logout"

// render はページを描いて返す。
func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	t, ok := h.pages[page]
	if !ok {
		h.Log.Error("unknown page", "page", page)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h.execute(w, r, status, t, "layout", h.pageData(r, title, data))
}

func (h *Handler) pageData(r *http.Request, title string, data any) pageData {
	pd := pageData{Title: title, Version: h.Version, Mode: h.Mode, Dev: h.Identifier.Dev(), Data: data}
	if !pd.Dev {
		pd.LogoutURL = accessLogoutURL
	}
	if a := actorFrom(r.Context()); a.Operator != "" {
		pd.User = a.Operator
		pd.Nav = nav
	}
	pd.Section, _, _ = strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return pd
}

// renderBlock はページの中の 1 つのテンプレート（htmx で差し替える部分）だけを描いて返す。
func (h *Handler) renderBlock(w http.ResponseWriter, r *http.Request, status int, page, block string, data any) {
	t, ok := h.pages[page]
	if !ok {
		h.Log.Error("unknown page", "page", page)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h.execute(w, r, status, t, block, data)
}

// renderPart は、htmx の要求なら block だけを、そうでなければページ全体を返す。
func (h *Handler) renderPart(w http.ResponseWriter, r *http.Request, status int, page, block, title string, data any) {
	if isHTMX(r) {
		h.renderBlock(w, r, status, page, block, data)
		return
	}
	h.render(w, r, status, page, title, data)
}

// isHTMX は htmx が送った要求か。
func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// execute はテンプレートを描いて返す。描くのに失敗したら 500 を返す（途中まで書き出さないよう、先にバッファーに描く）。
func (h *Handler) execute(w http.ResponseWriter, r *http.Request, status int, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		h.Log.ErrorContext(r.Context(), "render", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// seeOther は別の画面へ移動させる（htmx の要求では HX-Redirect で移動させる）。
func seeOther(w http.ResponseWriter, r *http.Request, to string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// errorData はエラーの画面に出す値。
type errorData struct {
	Status  int
	Message string
}

// renderError はエラーの画面を返す。htmx の要求では、差し替え先によらず本文全体をエラーの表示に置き換える。
func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	data := errorData{Status: status, Message: msg}
	title := http.StatusText(status)
	if isHTMX(r) {
		w.Header().Set("HX-Retarget", "main")
		w.Header().Set("HX-Reswap", "innerHTML")
		h.renderBlock(w, r, status, "error", "content", h.pageData(r, title, data))
		return
	}
	h.render(w, r, status, "error", title, data)
}
