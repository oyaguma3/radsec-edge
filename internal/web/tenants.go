package web

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// maxFormBytes はフォームの大きさの上限（証明書や CRL の貼り付けを含む）。
const maxFormBytes = 2 << 20

// tenantForm はテナントの作成・変更のフォームの値（誤りのときに入れた値を戻す）。
type tenantForm struct {
	Slug, Port, Auth, Acct, CRLURL string
}

// tenantsData はテナントの一覧の画面に出す値。
type tenantsData struct {
	overview
	Form  tenantForm
	Error string
	// Capacity と Free はポートの範囲の大きさと空き。
	Capacity, Free int
}

func (h *Handler) tenantList(w http.ResponseWriter, r *http.Request) {
	h.renderTenants(w, r, http.StatusOK, tenantForm{Auth: addrString(h.AuthUpstream), Acct: addrString(h.AcctUpstream)}, "")
}

func addrString(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func (h *Handler) renderTenants(w http.ResponseWriter, r *http.Request, status int, f tenantForm, errMsg string) {
	o, err := h.overview(r.Context())
	if err != nil {
		h.Log.Error("tenants", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	capacity := config.PortMax - config.PortMin + 1
	h.renderPart(w, r, status, "tenants", "tenants-section", "テナント",
		tenantsData{overview: o, Form: f, Error: errMsg, Capacity: capacity, Free: capacity - len(o.Rows)})
}

// readForm はフォームを読む（大きさの上限つき）。
func readForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

// parseTenantForm はテナントのフォームを読む。
func parseTenantForm(f tenantForm, needPort bool) (edge.TenantInput, error) {
	in := edge.TenantInput{Slug: f.Slug, CRLURL: f.CRLURL}
	if f.Port != "" || needPort {
		p, err := strconv.Atoi(f.Port)
		if err != nil {
			return in, &edge.InputError{Msg: "ポートは数字で入れてください"}
		}
		in.Port = p
	}
	var err error
	if in.Auth, err = config.ParseUpstream(f.Auth); err != nil {
		return in, &edge.InputError{Msg: "認証の上流は " + err.Error()}
	}
	if in.Acct, err = config.ParseUpstream(f.Acct); err != nil {
		return in, &edge.InputError{Msg: "課金の上流は " + err.Error()}
	}
	return in, nil
}

func formOf(r *http.Request) tenantForm {
	return tenantForm{Slug: strings.TrimSpace(r.PostFormValue("slug")), Port: strings.TrimSpace(r.PostFormValue("port")),
		Auth: strings.TrimSpace(r.PostFormValue("auth")), Acct: strings.TrimSpace(r.PostFormValue("acct")),
		CRLURL: strings.TrimSpace(r.PostFormValue("crl_url"))}
}

func (h *Handler) tenantCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	f := formOf(r)
	in, err := parseTenantForm(f, false)
	if err == nil {
		var t db.Tenant
		t, err = h.Edge.CreateTenant(ctx, actorFrom(ctx), in)
		if err == nil {
			seeOther(w, r, "/tenants/"+t.ID)
			return
		}
	}
	if edge.IsInput(err) {
		h.renderTenants(w, r, http.StatusUnprocessableEntity, f, err.Error())
		return
	}
	h.Log.Error("create tenant", "error", err)
	h.renderError(w, r, http.StatusInternalServerError, "テナントを作れませんでした。")
}

// certInfo は証明書の表示する値。
type certInfo struct {
	Subject, Issuer, Serial string
	NotAfter                time.Time
	DNS, URIs               []string
	// Expired と Soon は期限が切れたか、30 日を切ったか。
	Expired, Soon bool
}

func (h *Handler) certInfo(pemData string) *certInfo {
	if pemData == "" {
		return nil
	}
	c, err := pki.ParseCert([]byte(pemData))
	if err != nil {
		return &certInfo{Subject: "（読めない証明書: " + err.Error() + "）"}
	}
	return certInfoOf(c, h.Now())
}

func certInfoOf(c *x509.Certificate, now time.Time) *certInfo {
	ci := &certInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: pki.SerialHex(c), NotAfter: c.NotAfter, DNS: c.DNSNames}
	for _, u := range c.URIs {
		ci.URIs = append(ci.URIs, u.String())
	}
	ci.Expired = !now.Before(c.NotAfter)
	ci.Soon = !ci.Expired && c.NotAfter.Sub(now) < 30*24*time.Hour
	return ci
}

// apRow は AP の一覧の 1 行。
type apRow struct {
	db.AP
	SAN string
	// Expired と Soon は証明書の期限が切れたか、30 日を切ったか（証明書を取り込んでいなければ両方 false）。
	Expired, Soon bool
	// Seen は接続の状態（radsecproxy のログから。設計概要 §12.1）。
	Seen edge.SeenState
}

// tenantData はテナントの詳細の画面に出す値。
type tenantData struct {
	Tenant db.Tenant
	Form   tenantForm
	APs    []apRow
	// Container はテナントのコンテナ（なければ nil）、AgentError は agent に届かないときの理由。
	Container  *agent.Container
	AgentError string
	CRL        crlState
	CRLURL     string
	// Plan は未反映の変更（反映したときに変わること）、PlanError は求められなかった理由。
	Plan      edge.Plan
	PlanError string
	Applies   []db.Apply
	// DNSNames はスロットの DNS の名前（DNS に登録すべき名前。設計概要 §8.3）。
	DNSNames []string
	// 証明書の内容（なければ nil）。ServerPending と ProbePending は、CSR を出して証明書を待っている鍵があるか。
	ClientCA, ServerCert, ProbeCert *certInfo
	ServerPending, ProbePending     bool
	// ProbeSAN と URNPrefix は、ヘルスチェック用の証明書と AP の証明書の SAN の説明に使う。
	ProbeSAN, URNPrefix, DNSDomain string
	// CSR と CSRKind は、出した CSR（PEM）とその種類（server / probe）。
	CSR, CSRKind string
	// Message と Error は画面の上部の文。
	Message, Error string
	// APName は AP の登録のフォームの値（誤りのときに戻す）。
	APName string
}

// loadTenant は詳細の画面の値を集める。
func (h *Handler) loadTenant(ctx context.Context, id string) (tenantData, error) {
	t, err := h.DB.Tenant(ctx, id)
	if err != nil {
		return tenantData{}, err
	}
	d := tenantData{Tenant: t, Form: tenantForm{Slug: t.Slug, Port: strconv.Itoa(t.Port), Auth: t.AuthUpstream.String(),
		Acct: t.AcctUpstream.String(), CRLURL: t.CRLURL}, DNSNames: names.SlotNames(t.Slug, h.Edge.DNSDomain),
		ProbeSAN: names.SANURI(h.Edge.URNPrefix, t.Slug, names.ProbeAP), URNPrefix: h.Edge.URNPrefix, DNSDomain: h.Edge.DNSDomain,
		CRLURL: h.Edge.CRLURL(t)}
	aps, err := h.DB.APs(ctx, id)
	if err != nil {
		return tenantData{}, err
	}
	now := h.Now()
	for _, a := range aps {
		row := apRow{AP: a, SAN: names.SANURI(h.Edge.URNPrefix, t.Slug, a.Name)}
		if !a.CertNotAfter.IsZero() {
			row.Expired = !now.Before(a.CertNotAfter)
			row.Soon = !row.Expired && a.CertNotAfter.Sub(now) < 30*24*time.Hour
		}
		d.APs = append(d.APs, row)
	}
	crl, err := h.DB.CRL(ctx, id)
	if err != nil {
		return tenantData{}, err
	}
	d.CRL = h.crlState(crl)
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	st, err := h.Edge.Agent.Status(actx)
	cancel()
	if err != nil {
		d.AgentError = err.Error()
	} else if c, ok := st.Container(id); ok {
		d.Container = &c
	}
	var started time.Time
	if d.Container != nil && d.Container.Running {
		started = d.Container.StartedAt
	}
	seen, err := h.Edge.APSeen(ctx, id, started)
	if err != nil {
		return tenantData{}, err
	}
	for i := range d.APs {
		d.APs[i].Seen = seen[d.APs[i].Name]
	}
	if d.Plan, err = h.Edge.Plan(ctx, id); err != nil {
		d.PlanError = err.Error()
	}
	if d.Applies, err = h.DB.Applies(ctx, id, 20); err != nil {
		return tenantData{}, err
	}
	d.ClientCA, d.ServerCert, d.ProbeCert = h.certInfo(t.ClientCAPEM), h.certInfo(t.ServerCertPEM), h.certInfo(t.ProbeCertPEM)
	for _, k := range []struct {
		kind keystore.Kind
		dst  *bool
	}{{keystore.Server, &d.ServerPending}, {keystore.Probe, &d.ProbePending}} {
		p, err := h.Edge.Keys.Pending(id, k.kind)
		if err != nil {
			return tenantData{}, err
		}
		*k.dst = p != nil
	}
	return d, nil
}

func (h *Handler) tenant(w http.ResponseWriter, r *http.Request) {
	h.renderTenant(w, r, http.StatusOK, r.PathValue("id"), func(*tenantData) {})
}

// renderTenant は詳細の画面（htmx の要求なら、差し替える部分）を描く。mod で文などを足す。
func (h *Handler) renderTenant(w http.ResponseWriter, r *http.Request, status int, id string, mod func(*tenantData)) {
	d, err := h.loadTenant(r.Context(), id)
	if errors.Is(err, db.ErrNotFound) {
		h.renderError(w, r, http.StatusNotFound, "テナントが見つかりません。")
		return
	}
	if err != nil {
		h.Log.Error("load tenant", "tenant", id, "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "テナントを読めません。")
		return
	}
	mod(&d)
	h.renderPart(w, r, status, "tenant", "tenant-detail", "テナント "+d.Tenant.Slug, d)
}

// result は操作の結果で詳細の画面を描く。利用者の入力の誤りはそのまま見せ、それ以外はログに残して短い文を見せる。
func (h *Handler) result(w http.ResponseWriter, r *http.Request, id, op, okMsg string, err error, mod func(*tenantData)) {
	if mod == nil {
		mod = func(*tenantData) {}
	}
	switch {
	case err == nil:
		h.renderTenant(w, r, http.StatusOK, id, func(d *tenantData) { d.Message = okMsg; mod(d) })
	case errors.Is(err, db.ErrNotFound):
		h.renderError(w, r, http.StatusNotFound, "テナントか AP が見つかりません。")
	case edge.IsInput(err):
		h.renderTenant(w, r, http.StatusUnprocessableEntity, id, func(d *tenantData) { d.Error = err.Error(); mod(d) })
	default:
		h.Log.Error(op, "tenant", id, "error", err)
		h.renderTenant(w, r, http.StatusBadGateway, id, func(d *tenantData) { d.Error = op + "に失敗しました: " + err.Error(); mod(d) })
	}
}

func (h *Handler) tenantUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	f := formOf(r)
	in, err := parseTenantForm(f, true)
	if err == nil {
		_, err = h.Edge.UpdateTenant(ctx, actorFrom(ctx), id, in)
	}
	h.result(w, r, id, "テナントの変更", "テナントの設定を変えました。反映すると radsecproxy に効きます。", err, func(d *tenantData) {
		if err != nil {
			f.Slug = d.Tenant.Slug
			d.Form = f
		}
	})
}

func (h *Handler) tenantDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	err := h.Edge.DeleteTenant(ctx, actorFrom(ctx), id)
	if err == nil {
		seeOther(w, r, "/tenants")
		return
	}
	h.result(w, r, id, "テナントの削除", "", err, nil)
}

func (h *Handler) tenantApply(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	rec, err := h.Edge.Apply(ctx, actorFrom(ctx), id)
	msg := "反映しました（版 " + strconv.FormatInt(rec.Version, 10) + "、" + actionLabel(rec.Action) + "）。ヘルスチェックも通りました。"
	if err != nil && !edge.IsInput(err) && rec.Result != "" {
		// 反映の失敗（前の版のまま・前の版に戻した）は、理由を見せる。
		err = &edge.InputError{Msg: resultLabel(rec.Result) + ": " + err.Error()}
	}
	h.result(w, r, id, "反映", msg, err, nil)
}

func (h *Handler) tenantRestart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	err := h.Edge.Restart(ctx, actorFrom(ctx), id)
	if errors.Is(err, agent.ErrNotFound) {
		err = &edge.InputError{Msg: "コンテナがありません（まだ反映していないか、停止しています）"}
	}
	h.result(w, r, id, "再起動", "再起動しました。", err, nil)
}

func (h *Handler) tenantStop(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	h.result(w, r, id, "停止", "停止しました。起動するまで、このテナントの AP はこのエッジにつながりません。",
		h.Edge.SetEnabled(ctx, actorFrom(ctx), id, false), nil)
}

func (h *Handler) tenantStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	h.result(w, r, id, "起動", "起動しました。", h.Edge.SetEnabled(ctx, actorFrom(ctx), id, true), nil)
}

// logsData はログの末尾の表示。
type logsData struct {
	Logs, Error string
}

func (h *Handler) tenantLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !names.ValidSlug(id) {
		h.renderError(w, r, http.StatusNotFound, "テナントが見つかりません。")
		return
	}
	var d logsData
	logs, err := h.Edge.Agent.Logs(r.Context(), id, 200)
	switch {
	case errors.Is(err, agent.ErrNotFound):
		d.Error = "コンテナがありません。"
	case err != nil:
		d.Error = "ログを読めません: " + err.Error()
	default:
		d.Logs = logs
	}
	h.renderBlock(w, r, http.StatusOK, "tenant", "logs", d)
}

func (h *Handler) clientCAImport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	err := h.Edge.ImportClientCA(ctx, actorFrom(ctx), id, []byte(r.PostFormValue("pem")))
	msg := "クライアントCA の証明書を取り込みました。"
	if err == nil {
		// CRL をすぐ取りに行く（取得先がなければ、CRL を貼り付けて取り込む）。
		if t, terr := h.DB.Tenant(ctx, id); terr == nil && h.Edge.CRLURL(t) != "" {
			if cerr := h.Edge.RefreshCRL(ctx, actorFrom(ctx), id); cerr != nil {
				msg += "CRL は取得できませんでした（" + cerr.Error() + "）。"
			} else {
				msg += "CRL も取得しました。"
			}
		}
	}
	h.result(w, r, id, "クライアントCA の取り込み", msg, err, nil)
}

// kindOf はパスの証明書の種類を返す。
func kindOf(r *http.Request) (keystore.Kind, string, bool) {
	switch r.PathValue("kind") {
	case "server":
		return keystore.Server, "サーバー証明書", true
	case "probe":
		return keystore.Probe, "ヘルスチェック用の証明書", true
	}
	return "", "", false
}

func (h *Handler) csrCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	kind, label, ok := kindOf(r)
	if !ok {
		h.notFound(w, r)
		return
	}
	csr, err := h.Edge.CSR(ctx, actorFrom(ctx), id, kind)
	h.result(w, r, id, label+"の CSR", label+"の CSR を作りました。CA で署名して、できた証明書を取り込んでください。", err, func(d *tenantData) {
		d.CSR, d.CSRKind = string(csr), string(kind)
	})
}

func (h *Handler) certImport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	kind, label, ok := kindOf(r)
	if !ok {
		h.notFound(w, r)
		return
	}
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	err := h.Edge.ImportCert(ctx, actorFrom(ctx), id, kind, []byte(r.PostFormValue("pem")))
	h.result(w, r, id, label+"の取り込み", label+"を取り込みました。反映すると radsecproxy に効きます。", err, nil)
}

func (h *Handler) crlUpload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	err := h.Edge.InstallCRL(ctx, actorFrom(ctx), id, []byte(r.PostFormValue("pem")))
	h.result(w, r, id, "CRL の取り込み", "CRL を取り込みました（反映済みの版があれば、SIGHUP で読み直させました）。", err, nil)
}

func (h *Handler) crlRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	err := h.Edge.RefreshCRL(ctx, actorFrom(ctx), id)
	h.result(w, r, id, "CRL の取得", "CRL を取りに行きました（変わっていれば、SIGHUP で読み直させました）。", err, nil)
}

func (h *Handler) apPut(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id := r.PathValue("id")
	if err := readForm(w, r); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "フォームを読めません。")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	_, err := h.Edge.PutAP(ctx, actorFrom(ctx), id, name, []byte(r.PostFormValue("pem")))
	h.result(w, r, id, "AP の登録", "AP "+name+" を登録しました。反映すると、この AP がつながるようになります。", err, func(d *tenantData) {
		if err != nil {
			d.APName = name
		}
	})
}

func (h *Handler) apDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.opContext(r)
	defer cancel()
	id, name := r.PathValue("id"), r.PathValue("name")
	err := h.Edge.DeleteAP(ctx, actorFrom(ctx), id, name)
	h.result(w, r, id, "AP の削除", "AP "+name+" を削除しました。次の反映で設定から消えます（すぐに止めるには、CA で証明書を失効させます）。", err, nil)
}
