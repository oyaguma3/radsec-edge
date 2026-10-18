package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
)

// crlState はテナントの CRL の状態（画面に出す警告。設計概要 §9.5）。
type crlState struct {
	db.CRL
	// Missing は CRL がまだないこと、Expired は nextUpdate を過ぎたこと、Warn は残りが EDGE_CRL_WARN を切ったこと。
	Missing, Expired, Warn bool
	// Remaining は nextUpdate までの残り。
	Remaining time.Duration
}

// Problem は警告を出すべき状態か（CRL がない、期限が近い・切れた、最後の取得に失敗した）。
func (c crlState) Problem() bool { return c.Missing || c.Expired || c.Warn || c.LastError != "" }

// RemainingText は残りを「n 日 m 時間」で表す。
func (c crlState) RemainingText() string {
	d := c.Remaining
	if d <= 0 {
		return "0"
	}
	days := int(d / (24 * time.Hour))
	hours := int((d % (24 * time.Hour)) / time.Hour)
	if days > 0 {
		return strconv.Itoa(days) + " 日 " + strconv.Itoa(hours) + " 時間"
	}
	return strconv.Itoa(hours) + " 時間 " + strconv.Itoa(int((d%time.Hour)/time.Minute)) + " 分"
}

func (h *Handler) crlState(c db.CRL) crlState {
	s := crlState{CRL: c, Missing: c.PEM == ""}
	if !s.Missing {
		s.Remaining = c.NextUpdate.Sub(h.Now())
		s.Expired = s.Remaining <= 0
		s.Warn = !s.Expired && s.Remaining < h.CRLWarn
	}
	return s
}

// tenantRow は一覧とダッシュボードのテナントの 1 行。
type tenantRow struct {
	db.Tenant
	APs int
	// Container はテナントのコンテナ（なければ nil）。
	Container *agent.Container
	CRL       crlState
	// ProbeProblem はヘルスチェック用の証明書の問題（失効など。なければ空）。
	ProbeProblem string
}

// ContainerProblem は、起動しているテナントで反映済みなのに、コンテナが動いていないか。
func (t tenantRow) ContainerProblem() bool {
	return t.Enabled && t.AppliedVersion > 0 && (t.Container == nil || !t.Container.Running)
}

// overview はすべてのテナントの行と agent の状態。
type overview struct {
	Rows  []tenantRow
	Agent agent.Status
	// AgentError は agent の状態を取れなかった理由（取れなければ Agent は空）。
	AgentError string
}

// overview はすべてのテナントの行を作る。
func (h *Handler) overview(ctx context.Context) (overview, error) {
	tenants, err := h.DB.Tenants(ctx)
	if err != nil {
		return overview{}, err
	}
	counts, err := h.DB.CountAPs(ctx)
	if err != nil {
		return overview{}, err
	}
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	st, agentErr := h.Edge.Agent.Status(actx)
	cancel()
	o := overview{Agent: st}
	if agentErr != nil {
		o.AgentError = agentErr.Error()
	}
	for _, t := range tenants {
		r := tenantRow{Tenant: t, APs: counts[t.ID]}
		if c, ok := st.Container(t.ID); ok {
			r.Container = &c
		}
		crl, err := h.DB.CRL(ctx, t.ID)
		if err != nil {
			return overview{}, err
		}
		r.CRL = h.crlState(crl)
		if r.ProbeProblem, err = h.Edge.ProbeProblem(ctx, t); err != nil {
			return overview{}, err
		}
		o.Rows = append(o.Rows, r)
	}
	return o, nil
}

// homeData はダッシュボード（設計概要 §13.1）に出す値。
type homeData struct {
	Mode string
	// Agent は agent の状態、AgentError は agent に届かないときの理由。
	Agent      agent.Status
	AgentError string
	Reconcile  edge.ReconcileState
	// Tenants はテナントの数、Capacity はポートの範囲から決まる上限。
	Tenants, Capacity int
	// Pending は未反映の変更のあるテナント、CRLProblems は CRL に警告のあるテナント、Down はコンテナが動いていないテナント、
	// ProbeProblems はヘルスチェック用の証明書に問題のあるテナント。
	Pending, CRLProblems, Down, ProbeProblems []tenantRow
	CRLWarn                                   time.Duration
}

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	o, err := h.overview(r.Context())
	if err != nil {
		h.Log.Error("home", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	d := homeData{Mode: h.Mode, Agent: o.Agent, AgentError: o.AgentError, Reconcile: h.Edge.LastReconcile(), Tenants: len(o.Rows),
		Capacity: config.PortMax - config.PortMin + 1, CRLWarn: h.CRLWarn}
	for _, t := range o.Rows {
		if t.Pending() {
			d.Pending = append(d.Pending, t)
		}
		if t.ClientCAPEM != "" && t.CRL.Problem() {
			d.CRLProblems = append(d.CRLProblems, t)
		}
		if t.ProbeProblem != "" {
			d.ProbeProblems = append(d.ProbeProblems, t)
		}
		if o.AgentError == "" && t.ContainerProblem() {
			d.Down = append(d.Down, t)
		}
	}
	h.render(w, r, http.StatusOK, "home", "ダッシュボード", d)
}

// auditData は監査ログの画面に出す値。
type auditData struct {
	Entries []db.AuditEntry
	// More は続きの URL（なければ空）。
	More string
}

const auditPage = 100

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	var before int64
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			h.renderError(w, r, http.StatusBadRequest, "before の値が正しくありません。")
			return
		}
		before = n
	}
	es, err := h.DB.ListAudit(r.Context(), before, auditPage+1)
	if err != nil {
		h.Log.Error("audit", "error", err)
		h.renderError(w, r, http.StatusServiceUnavailable, "データベースを読めません。")
		return
	}
	d := auditData{Entries: es}
	if len(es) > auditPage {
		d.Entries = es[:auditPage]
		d.More = "/audit?before=" + strconv.Itoa(int(d.Entries[auditPage-1].ID))
	}
	if before > 0 && isHTMX(r) {
		h.renderBlock(w, r, http.StatusOK, "audit", "audit-rows", d)
		return
	}
	h.render(w, r, http.StatusOK, "audit", "監査ログ", d)
}
