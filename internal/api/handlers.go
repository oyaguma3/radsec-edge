package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// maxLogLines は GET /tenants/{tenantId}/logs の行数の上限（§24.11 の EA10）。
const (
	defaultLogLines = 200
	maxLogLines     = 1000
)

// opContext は同期の変更の口のコンテキスト。呼び出し側が接続を切っても中途半端に止まらないよう、要求の取り消しからは切り離す。
func opContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
}

// utcOrZero は時刻を UTC にする（ゼロ値はそのまま）。
func utcOrZero(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

type containerJSON struct {
	State        string    `json:"state"`
	Running      bool      `json:"running"`
	Restarting   bool      `json:"restarting,omitzero"`
	RestartCount int       `json:"restartCount,omitzero"`
	StartedAt    time.Time `json:"startedAt,omitzero"`
	Port         int       `json:"port,omitzero"`
}

// applyJSON は裏の反映の状態と、最後の反映の結果（§24.11 の EA5）。
type applyJSON struct {
	// State は idle か running。
	State      string    `json:"state"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	LastResult string    `json:"lastResult,omitempty"`
	LastError  string    `json:"lastError,omitempty"`
	// LastRevision は最後の反映の対象の版。LastFinishedAt はその終わった時刻。
	LastRevision   int64     `json:"lastRevision,omitzero"`
	LastFinishedAt time.Time `json:"lastFinishedAt,omitzero"`
}

// summaryJSON は GET /tenants の 1 行（証明書の本体と AP は含めない。§24.11 の EA9）。
type summaryJSON struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
	// Revision は最後に受け取った宣言の版、AppliedRevision は反映済みの版。Pending は未反映の変更があるか（証明書の更新を含む。EA3）。
	Revision        int64 `json:"revision"`
	AppliedRevision int64 `json:"appliedRevision"`
	Pending         bool  `json:"pending"`
	// ConfigHash は反映済みの設定のハッシュ。
	ConfigHash string    `json:"configHash,omitempty"`
	AppliedAt  time.Time `json:"appliedAt,omitzero"`
	// Missing は反映に足りないもの。ProbeProblem はヘルスチェック用の証明書の問題。
	Missing      []string       `json:"missing"`
	ProbeProblem string         `json:"probeProblem,omitempty"`
	Apply        applyJSON      `json:"apply"`
	Container    *containerJSON `json:"container,omitempty"`
	APCount      int            `json:"apCount"`
}

type crlJSON struct {
	CAID          string    `json:"caId"`
	Number        string    `json:"number,omitempty"`
	ThisUpdate    time.Time `json:"thisUpdate,omitzero"`
	NextUpdate    time.Time `json:"nextUpdate,omitzero"`
	LastAttemptAt time.Time `json:"lastAttemptAt,omitzero"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitzero"`
	LastError     string    `json:"lastError,omitempty"`
	// OK は CRL があり、最後の取得に失敗していないか。Expired は nextUpdate を過ぎたか。Warn は残りが EDGE_CRL_WARN を切ったか。
	OK      bool `json:"ok"`
	Expired bool `json:"expired,omitzero"`
	Warn    bool `json:"warn,omitzero"`
}

func (h *Handler) crlJSON(r edge.CRLReport) crlJSON {
	c := r.CA
	out := crlJSON{CAID: r.CAID, Number: c.Number, ThisUpdate: utcOrZero(c.ThisUpdate), NextUpdate: utcOrZero(c.NextUpdate),
		LastAttemptAt: utcOrZero(c.LastAttemptAt), LastSuccessAt: utcOrZero(c.LastSuccessAt), LastError: c.LastError, OK: r.OK}
	if c.PEM != "" {
		left := c.NextUpdate.Sub(h.now())
		out.Expired, out.Warn = left <= 0, left > 0 && left < h.CRLWarn
	}
	return out
}

type certInfoJSON struct {
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"notAfter"`
	Subject  string    `json:"subject"`
}

func certInfo(certPEM string) *certInfoJSON {
	if certPEM == "" {
		return nil
	}
	c, err := pki.ParseCert([]byte(certPEM))
	if err != nil {
		return nil
	}
	return &certInfoJSON{Serial: pki.SerialHex(c), NotAfter: c.NotAfter.UTC(), Subject: c.Subject.String()}
}

type clientCAOut struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Subject    string    `json:"subject"`
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"notAfter"`
	SelfSigned bool      `json:"selfSigned"`
	HasCRL     bool      `json:"hasCrl"`
}

type apJSON struct {
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	Purpose      string    `json:"purpose,omitempty"`
	NASID        string    `json:"nasId,omitempty"`
	CertSerial   string    `json:"certSerial,omitempty"`
	CertNotAfter time.Time `json:"certNotAfter,omitzero"`
}

type matchJSON struct {
	Attr    string `json:"attr"`
	Pattern string `json:"pattern"`
}

// tenantJSON は GET /tenants/{tenantId} の応答。
type tenantJSON struct {
	summaryJSON  `json:",inline"`
	AuthUpstream string         `json:"authUpstream"`
	AcctUpstream string         `json:"acctUpstream"`
	ClientCAs    []clientCAOut  `json:"clientCas"`
	CRLs         []crlJSON      `json:"crls"`
	SharedMatch  *matchJSON     `json:"sharedMatch,omitempty"`
	SourceCIDRs  []string       `json:"sourceCidrs"`
	APs          []apJSON       `json:"aps"`
	ServerCert   *certInfoJSON  `json:"serverCert,omitempty"`
	ProbeCert    *certInfoJSON  `json:"probeCert,omitempty"`
	Applies      []applyLogJSON `json:"applies"`
}

type applyLogJSON struct {
	Revision int64     `json:"revision,omitzero"`
	Trigger  string    `json:"trigger"`
	Action   string    `json:"action,omitempty"`
	Result   string    `json:"result"`
	Error    string    `json:"error,omitempty"`
	Operator string    `json:"operator,omitempty"`
	Started  time.Time `json:"startedAt"`
	Finished time.Time `json:"finishedAt"`
}

// applyState は裏の反映の状態と最後の結果を読む。呼び出し側はテナントの行と agent の状態をこの後に読む（反映が終わったと見せるときは、
// 反映の前の行や写しを見せない）。動いているかを先に読む（裏の反映は、記録を書いてから終わりにする）。
func (h *Handler) applyState(ctx context.Context, id string) (applyJSON, error) {
	out := applyJSON{State: "idle"}
	if at, running := h.Edge.ApplyRunning(id); running {
		out.State, out.StartedAt = "running", at.UTC()
	}
	last, err := h.DB.LastApply(ctx, id)
	switch {
	case err == nil:
		out.LastResult, out.LastError, out.LastRevision, out.LastFinishedAt = last.Result, last.Error, last.Revision, last.Finished.UTC()
	case !errors.Is(err, db.ErrNotFound):
		return out, err
	}
	return out, nil
}

// summary はテナントの要約を作る（st は agent の状態を返す。取れなければゼロ値で、コンテナは出さない）。
func (h *Handler) summary(ctx context.Context, t db.Tenant, apply applyJSON, st func() agent.Status, apCount int) (summaryJSON, error) {
	out := summaryJSON{ID: t.ID, Slug: t.Slug, Port: t.Port, Enabled: t.Enabled, Revision: t.Revision, AppliedRevision: t.AppliedRevision, Pending: t.Pending(),
		ConfigHash: t.AppliedHash, AppliedAt: utcOrZero(t.AppliedAt), APCount: apCount, Apply: apply}
	var err error
	if out.Missing, err = h.Edge.Missing(ctx, t); err != nil {
		return out, err
	}
	if out.Missing == nil {
		out.Missing = []string{}
	}
	if out.ProbeProblem, err = h.Edge.ProbeProblem(ctx, t); err != nil {
		return out, err
	}
	if c, ok := st().Container(t.ID); ok {
		out.Container = &containerJSON{State: c.State, Running: c.Running, Restarting: c.Restarting, RestartCount: c.RestartCount, StartedAt: utcOrZero(c.StartedAt), Port: c.Port}
	}
	return out, nil
}

// agentStatus は agent の状態を使い回して返す（読み出しの口は、agent に届かなくても DB の値を返す）。
func (h *Handler) agentStatus(ctx context.Context) (agent.Status, string) {
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := h.Edge.AgentStatus(actx)
	if err != nil {
		h.Log.WarnContext(ctx, "cannot read the agent status", "error", err)
		return agent.Status{}, err.Error()
	}
	return st, ""
}

// status はエッジの状態（§24.11 の EA12）。
func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := h.DB.Tenants(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	st, agentErr := h.agentStatus(ctx)
	type tenantCRLs struct {
		ID   string    `json:"id"`
		Slug string    `json:"slug"`
		CRLs []crlJSON `json:"crls"`
	}
	type agentJSON struct {
		OK             bool   `json:"ok"`
		Error          string `json:"error,omitempty"`
		Version        string `json:"version,omitempty"`
		DockerOK       bool   `json:"dockerOk"`
		DockerError    string `json:"dockerError,omitempty"`
		Image          string `json:"image,omitempty"`
		ImagePresent   bool   `json:"imagePresent"`
		Network        string `json:"network,omitempty"`
		NetworkPresent bool   `json:"networkPresent"`
	}
	type capacityJSON struct {
		Max  int `json:"max"`
		Used int `json:"used"`
		Free int `json:"free"`
	}
	type stampJSON struct {
		VendorID   int `json:"vendorId"`
		VendorType int `json:"vendorType"`
	}
	type reconcileJSON struct {
		At    time.Time `json:"at,omitzero"`
		Error string    `json:"error,omitempty"`
	}
	rec := h.Edge.LastReconcile()
	out := struct {
		Service      string        `json:"service"`
		Version      string        `json:"version"`
		Mode         string        `json:"mode"`
		URNPrefix    string        `json:"urnPrefix"`
		DNSDomain    string        `json:"dnsDomain"`
		Stamp        stampJSON     `json:"stamp"`
		Agent        agentJSON     `json:"agent"`
		Capacity     capacityJSON  `json:"capacity"`
		Reconcile    reconcileJSON `json:"reconcile"`
		AdminClients []string      `json:"adminClients"`
		Tenants      []tenantCRLs  `json:"tenants"`
	}{Service: "radsec-edge", Version: h.Version, Mode: h.Mode, URNPrefix: h.Edge.URNPrefix, DNSDomain: h.Edge.DNSDomain,
		Stamp: stampJSON{h.Edge.Stamp.VendorID, h.Edge.Stamp.VendorType},
		Agent: agentJSON{OK: agentErr == "", Error: agentErr, Version: st.Version, DockerOK: st.DockerOK, DockerError: st.DockerError, Image: st.Image,
			ImagePresent: st.ImagePresent, Network: st.Network, NetworkPresent: st.NetworkPresent},
		Capacity:  capacityJSON{Max: h.Edge.Capacity, Used: len(tenants), Free: max(h.Edge.Capacity-len(tenants), 0)},
		Reconcile: reconcileJSON{At: utcOrZero(rec.At), Error: rec.Error}, AdminClients: []string{}, Tenants: []tenantCRLs{}}
	if h.AdminClients != nil {
		out.AdminClients = h.AdminClients()
	}
	for _, t := range tenants {
		reports, err := h.Edge.CRLReports(ctx, t)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		row := tenantCRLs{ID: t.ID, Slug: t.Slug, CRLs: []crlJSON{}}
		for _, rp := range reports {
			row.CRLs = append(row.CRLs, h.crlJSON(rp))
		}
		out.Tenants = append(out.Tenants, row)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) listTenants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := h.DB.Tenants(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// 反映の状態を読んでからテナントの行を読み直す（applyState）。
	applies := map[string]applyJSON{}
	for _, t := range tenants {
		if applies[t.ID], err = h.applyState(ctx, t.ID); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if tenants, err = h.DB.Tenants(ctx); err != nil {
		h.fail(w, r, err)
		return
	}
	counts, err := h.DB.CountAPs(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	st := sync.OnceValue(func() agent.Status {
		v, _ := h.agentStatus(ctx)
		return v
	})
	items := []summaryJSON{}
	for _, t := range tenants {
		a, ok := applies[t.ID]
		if !ok {
			a.State = "idle" // 読み直しの間にできたテナント
		}
		s, err := h.summary(ctx, t, a, st, counts[t.ID])
		if err != nil {
			h.fail(w, r, err)
			return
		}
		items = append(items, s)
	}
	writeJSON(w, http.StatusOK, struct {
		Items []summaryJSON `json:"items"`
	}{items})
}

func (h *Handler) detail(ctx context.Context, t db.Tenant, apply applyJSON) (tenantJSON, error) {
	aps, err := h.DB.APs(ctx, t.ID)
	if err != nil {
		return tenantJSON{}, err
	}
	sum, err := h.summary(ctx, t, apply, func() agent.Status {
		v, _ := h.agentStatus(ctx)
		return v
	}, len(aps))
	if err != nil {
		return tenantJSON{}, err
	}
	out := tenantJSON{summaryJSON: sum, AuthUpstream: t.AuthUpstream.String(), AcctUpstream: t.AcctUpstream.String(), ClientCAs: []clientCAOut{}, CRLs: []crlJSON{},
		SourceCIDRs: []string{}, APs: []apJSON{}, ServerCert: certInfo(t.ServerCertPEM), ProbeCert: certInfo(t.ProbeCertPEM), Applies: []applyLogJSON{}}
	addCA := func(id, kind, certPEM string, hasCRL bool) {
		c, err := pki.ParseCert([]byte(certPEM))
		if err != nil {
			return
		}
		out.ClientCAs = append(out.ClientCAs, clientCAOut{ID: id, Kind: kind, Subject: c.Subject.String(), Serial: pki.SerialHex(c), NotAfter: c.NotAfter.UTC(),
			SelfSigned: pki.IsSelfSigned(c), HasCRL: hasCRL})
	}
	addCA("tenant."+t.Slug, caKindIssued, t.ClientCAPEM, true)
	brought, err := h.DB.BroughtCAs(ctx, t.ID)
	if err != nil {
		return tenantJSON{}, err
	}
	for _, b := range brought {
		addCA(b.CAID, caKindBrought, b.CertPEM, b.HasCRL)
	}
	reports, err := h.Edge.CRLReports(ctx, t)
	if err != nil {
		return tenantJSON{}, err
	}
	for _, rp := range reports {
		out.CRLs = append(out.CRLs, h.crlJSON(rp))
	}
	if t.SharedMatchAttr != "" {
		out.SharedMatch = &matchJSON{t.SharedMatchAttr, t.SharedMatchPattern}
	}
	for _, p := range t.SourceCIDRs {
		out.SourceCIDRs = append(out.SourceCIDRs, p.String())
	}
	for _, a := range aps {
		out.APs = append(out.APs, apJSON{Name: a.Name, Kind: a.Kind, Purpose: a.Purpose, NASID: a.NASID, CertSerial: a.CertSerial, CertNotAfter: utcOrZero(a.CertNotAfter)})
	}
	applies, err := h.DB.Applies(ctx, t.ID, 10)
	if err != nil {
		return tenantJSON{}, err
	}
	for _, a := range applies {
		out.Applies = append(out.Applies, applyLogJSON{Revision: a.Revision, Trigger: a.Trigger, Action: a.Action, Result: a.Result, Error: a.Error, Operator: a.Operator,
			Started: a.Started.UTC(), Finished: a.Finished.UTC()})
	}
	return out, nil
}

func (h *Handler) writeTenant(w http.ResponseWriter, r *http.Request, status int, id string) {
	ctx := r.Context()
	apply, err := h.applyState(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	t, err := h.DB.Tenant(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out, err := h.detail(ctx, t, apply)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, status, out)
}

func (h *Handler) getTenant(w http.ResponseWriter, r *http.Request) {
	h.writeTenant(w, r, http.StatusOK, r.PathValue("tenantId"))
}

// CA の種類（宣言の clientCas の kind。§24.6）。
const (
	caKindIssued  = "issued"
	caKindBrought = "brought"
)

// putTenant はテナントの望む状態をまるごと受け取る（§24.11 の EA2）。
func (h *Handler) putTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision     int64  `json:"revision"`
		Slug         string `json:"slug"`
		Port         int    `json:"port"`
		AuthUpstream string `json:"authUpstream"`
		AcctUpstream string `json:"acctUpstream"`
		ClientCAs    []struct {
			ID          string `json:"id"`
			Kind        string `json:"kind"`
			Certificate string `json:"certificate"`
			HasCRL      bool   `json:"hasCrl"`
		} `json:"clientCas"`
		SharedMatch *matchJSON `json:"sharedMatch"`
		SourceCIDRs []string   `json:"sourceCidrs"`
		APs         []struct {
			Name         string    `json:"name"`
			Kind         string    `json:"kind"`
			Purpose      string    `json:"purpose"`
			CertSerial   string    `json:"certSerial"`
			CertNotAfter time.Time `json:"certNotAfter"`
		} `json:"aps"`
	}
	if p := readJSON(r, &req); p != nil {
		p.write(w)
		return
	}
	d := edge.Declaration{ID: r.PathValue("tenantId"), Slug: req.Slug, Revision: req.Revision, Port: req.Port}
	var err error
	if d.Auth, err = config.ParseUpstream(req.AuthUpstream); err != nil {
		badRequest("authUpstream", err.Error()).write(w)
		return
	}
	if d.Acct, err = config.ParseUpstream(req.AcctUpstream); err != nil {
		badRequest("acctUpstream", err.Error()).write(w)
		return
	}
	for _, c := range req.ClientCAs {
		switch c.Kind {
		case caKindIssued:
			if d.IssuedCAID != "" {
				badRequest("clientCas", "exactly one CA of kind issued is required").write(w)
				return
			}
			if !c.HasCRL {
				badRequest("clientCas", "a CA of kind issued must have a CRL").write(w)
				return
			}
			d.IssuedCAID, d.IssuedCAPEM = c.ID, []byte(c.Certificate)
		case caKindBrought:
			d.Trust.Brought = append(d.Trust.Brought, edge.BroughtInput{CAID: c.ID, CertPEM: []byte(c.Certificate), HasCRL: c.HasCRL})
		default:
			badRequest("clientCas", "kind must be issued or brought").write(w)
			return
		}
	}
	if d.IssuedCAID == "" {
		badRequest("clientCas", "exactly one CA of kind issued is required").write(w)
		return
	}
	if req.SharedMatch != nil {
		d.Trust.SharedMatch = rsconf.Match{Attr: req.SharedMatch.Attr, Pattern: req.SharedMatch.Pattern}
	}
	for _, c := range req.SourceCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			badRequest("sourceCidrs", "must be CIDR ranges such as 192.0.2.0/24").write(w)
			return
		}
		d.Trust.SourceCIDRs = append(d.Trust.SourceCIDRs, p.Masked())
	}
	for _, a := range req.APs {
		d.APs = append(d.APs, edge.APDecl{Name: a.Name, Kind: a.Kind, Purpose: a.Purpose, CertSerial: a.CertSerial, CertNotAfter: a.CertNotAfter})
	}
	ctx, cancel := opContext(r)
	defer cancel()
	res, err := h.Edge.Declare(ctx, actor(r), d)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	h.writeTenant(w, r, status, d.ID)
}

func (h *Handler) deleteTenant(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := opContext(r)
	defer cancel()
	if err := h.Edge.DeleteTenant(ctx, actor(r), r.PathValue("tenantId")); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// csr はテナントのサーバー証明書かヘルスチェック用の証明書の鍵を作り、CSR を返す（鍵はエッジの外に出さない）。
func (h *Handler) csr(kind keystore.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := opContext(r)
		defer cancel()
		csr, err := h.Edge.CSR(ctx, actor(r), r.PathValue("tenantId"), kind)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			CSR string `json:"csr"`
		}{string(csr)})
	}
}

func (h *Handler) putCert(kind keystore.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Certificate string `json:"certificate"`
		}
		if p := readJSON(r, &req); p != nil {
			p.write(w)
			return
		}
		ctx, cancel := opContext(r)
		defer cancel()
		id := r.PathValue("tenantId")
		if err := h.Edge.ImportCert(ctx, actor(r), id, kind, []byte(req.Certificate)); err != nil {
			h.fail(w, r, err)
			return
		}
		h.writeTenant(w, r, http.StatusOK, id)
	}
}

// apply は反映を裏で始める（§24.11 の EA5）。結果は GET /tenants/{tenantId} の apply と appliedRevision で見る。
func (h *Handler) apply(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("tenantId")
	started, err := h.Edge.StartApply(r.Context(), actor(r), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	at, _ := h.Edge.ApplyRunning(id)
	writeJSON(w, http.StatusAccepted, struct {
		Started   bool      `json:"started"`
		State     string    `json:"state"`
		StartedAt time.Time `json:"startedAt,omitzero"`
	}{started, "running", utcOrZero(at)})
}

// refreshCRL は CRL をすぐ取りに行き、CA ごとの結果を返す（§24.11 の EA8）。
func (h *Handler) refreshCRL(w http.ResponseWriter, r *http.Request) {
	reports, msg, err := h.Edge.RefreshCRLReport(r.Context(), actor(r), r.PathValue("tenantId"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := []crlJSON{}
	for _, rp := range reports {
		items = append(items, h.crlJSON(rp))
	}
	writeJSON(w, http.StatusOK, struct {
		OK    bool      `json:"ok"`
		Error string    `json:"error,omitempty"`
		Items []crlJSON `json:"items"`
	}{msg == "" && !slices.ContainsFunc(items, func(c crlJSON) bool { return !c.OK }), msg, items})
}

func (h *Handler) restart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("tenantId")
	t, err := h.DB.Tenant(r.Context(), id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !t.Enabled {
		h.fail(w, r, &edge.InputError{Msg: "停止しているテナントは再起動できません", Cause: edge.CauseTenantStopped})
		return
	}
	ctx, cancel := opContext(r)
	defer cancel()
	if err := h.Edge.Restart(ctx, actor(r), id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) logs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("tenantId")
	if _, err := h.DB.Tenant(r.Context(), id); err != nil {
		h.fail(w, r, err)
		return
	}
	lines := defaultLogLines
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLogLines {
			badRequest("lines", "must be an integer between 1 and "+strconv.Itoa(maxLogLines)).write(w)
			return
		}
		lines = n
	}
	out, err := h.Edge.Agent.Logs(r.Context(), id, lines)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Logs string `json:"logs"`
	}{out})
}

// lastSeen は AP・グループごとの接続の状態と、共通のブロックの送信元の IP ごとの接続の状態を返す（§12.1、§24.6）。
func (h *Handler) lastSeen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("tenantId")
	if _, err := h.DB.Tenant(ctx, id); err != nil {
		h.fail(w, r, err)
		return
	}
	aps, err := h.DB.APs(ctx, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	st, _ := h.agentStatus(ctx)
	var started time.Time
	if c, ok := st.Container(id); ok && c.Running {
		started = c.StartedAt
	}
	seen, err := h.Edge.APSeen(ctx, id, started)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	shared, err := h.Edge.SharedSeen(ctx, id, started)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	type apSeen struct {
		Name       string    `json:"name"`
		Kind       string    `json:"kind"`
		Connected  bool      `json:"connected"`
		LastUp     time.Time `json:"lastUp,omitzero"`
		LastDown   time.Time `json:"lastDown,omitzero"`
		LastIP     string    `json:"lastIp,omitempty"`
		LastReject time.Time `json:"lastReject,omitzero"`
	}
	type sharedSeen struct {
		IP          string    `json:"ip"`
		Connections int       `json:"connections"`
		LastUp      time.Time `json:"lastUp,omitzero"`
		LastDown    time.Time `json:"lastDown,omitzero"`
	}
	out := struct {
		APs    []apSeen     `json:"aps"`
		Shared []sharedSeen `json:"shared"`
	}{[]apSeen{}, []sharedSeen{}}
	for _, a := range aps {
		s := seen[a.Name]
		out.APs = append(out.APs, apSeen{a.Name, a.Kind, s.Up, utcOrZero(s.LastUp), utcOrZero(s.LastDown), s.LastIP, utcOrZero(s.LastReject)})
	}
	for _, s := range shared {
		out.Shared = append(out.Shared, sharedSeen{s.IP, s.Connections, utcOrZero(s.LastUp), utcOrZero(s.LastDown)})
	}
	writeJSON(w, http.StatusOK, out)
}
