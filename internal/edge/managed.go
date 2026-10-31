package edge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// maxDeclaredAPs は 1 つの宣言の AP とグループの数の上限（§24.11 の EA2）。
const maxDeclaredAPs = 2000

// APDecl は宣言の AP かグループ。証明書の情報は表示だけ（照合は SAN で行うので、証明書の本体は受けない）。
type APDecl struct {
	Name string
	// Kind は db.KindAP か db.KindGroup、Purpose はグループの用途。
	Kind, Purpose string
	CertSerial    string
	CertNotAfter  time.Time
}

// Declaration は中央が送るテナントの望む状態の全部（§24.11 の EA2）。
type Declaration struct {
	ID, Slug string
	// Revision は中央が付けた版（EA3）。
	Revision   int64
	Port       int
	Auth, Acct netip.AddrPort
	// IssuedCAID と IssuedCAPEM は発行した CA。
	IssuedCAID  string
	IssuedCAPEM []byte
	Trust       TrustInput
	APs         []APDecl
}

// Declare はテナントの望む状態をまるごと置き換える（なければ作る。§24.11 の EA2）。反映するまで radsecproxy には効かない。
func (s *Service) Declare(ctx context.Context, a Actor, d Declaration) (db.DeclareResult, error) {
	if !names.ValidManagedID(d.ID) {
		return db.DeclareResult{}, invalid("テナントの ID は 1 以上の 10 進数（19 桁まで）にしてください")
	}
	if err := names.CheckTenant(d.Slug); err != nil {
		return db.DeclareResult{}, invalid("テナントの名前は、%v", err)
	}
	if d.Revision < 1 {
		return db.DeclareResult{}, invalid("revision は 1 以上にしてください")
	}
	if d.Port == 0 {
		return db.DeclareResult{}, invalid("ポートを入れてください")
	}
	if err := checkTenantInput(TenantInput{Port: d.Port, Auth: d.Auth, Acct: d.Acct}); err != nil {
		return db.DeclareResult{}, err
	}
	if want := "tenant." + d.Slug; d.IssuedCAID != want {
		return db.DeclareResult{}, invalid("発行した CA の ID は %s にしてください（%s）", want, d.IssuedCAID)
	}
	ca, err := pki.ParseCert(d.IssuedCAPEM)
	if err != nil {
		return db.DeclareResult{}, invalid("クライアントCA の証明書: %v", err)
	}
	if err := pki.CheckClientCA(ca, s.Now()); err != nil {
		return db.DeclareResult{}, invalid("クライアントCA の証明書: %v", err)
	}
	caPEM := certPEM(ca.Raw)
	cas, details, err := s.checkTrust(d.ID, d.Slug, caPEM, d.Trust)
	if err != nil {
		return db.DeclareResult{}, err
	}
	aps, err := checkDeclaredAPs(d.APs)
	if err != nil {
		return db.DeclareResult{}, err
	}
	unlock, err := s.acquire(ctx, d.ID)
	if err != nil {
		return db.DeclareResult{}, err
	}
	defer unlock()
	res, err := s.DB.Declare(ctx, db.Declaration{ID: d.ID, Slug: d.Slug, Revision: d.Revision, Port: d.Port, AuthUpstream: d.Auth, AcctUpstream: d.Acct,
		ClientCAPEM: caPEM, Brought: cas, SourceCIDRs: d.Trust.SourceCIDRs, MatchAttr: d.Trust.SharedMatch.Attr, MatchPattern: d.Trust.SharedMatch.Pattern,
		APs: aps, Capacity: s.Capacity})
	switch {
	case errors.Is(err, db.ErrSlugImmutable):
		return db.DeclareResult{}, invalidCause(CauseSlugImmutable, "テナントの名前（slug）は変えられません: %v", err)
	case errors.Is(err, db.ErrCapacity):
		return db.DeclareResult{}, invalidCause(CauseCapacityExceeded, "このエッジに置けるテナントの数（%d）に達しています", s.Capacity)
	case errors.Is(err, db.ErrConflict):
		return db.DeclareResult{}, invalidCause(CauseConflict, "ほかのテナントや AP と重なっています: %v", err)
	case err != nil:
		return db.DeclareResult{}, err
	}
	var cidrs []string
	for _, p := range d.Trust.SourceCIDRs {
		cidrs = append(cidrs, p.String())
	}
	s.audit(ctx, a, "tenant.declare", d.ID, map[string]any{"revision": d.Revision, "changed": res.Changed, "created": res.Created, "slug": d.Slug, "port": d.Port,
		"auth_upstream": d.Auth.String(), "acct_upstream": d.Acct.String(), "brought": details, "source_cidrs": cidrs,
		"shared_match_attr": d.Trust.SharedMatch.Attr, "shared_match_pattern": d.Trust.SharedMatch.Pattern, "aps": len(aps)})
	return res, nil
}

func checkDeclaredAPs(in []APDecl) ([]db.AP, error) {
	if len(in) > maxDeclaredAPs {
		return nil, invalid("AP とグループは %d 件までにしてください", maxDeclaredAPs)
	}
	seen := map[string]bool{}
	out := make([]db.AP, 0, len(in))
	for _, a := range in {
		switch a.Kind {
		case db.KindAP:
			if err := names.CheckAP(a.Name); err != nil {
				return nil, invalid("AP の名前（%s）は、%v", a.Name, err)
			}
			if a.Purpose != "" {
				return nil, invalid("AP %s に用途は書けません", a.Name)
			}
		case db.KindGroup:
			if err := names.CheckGroup(a.Name); err != nil {
				return nil, invalid("グループの名前（%s）は、%v", a.Name, err)
			}
			if !slices.Contains(groupPurposes, a.Purpose) {
				return nil, invalid("グループ %s の用途は %s のどれかにしてください", a.Name, strings.Join(groupPurposes, "・"))
			}
		default:
			return nil, invalid("%s の種類は ap か group にしてください", a.Name)
		}
		if seen[a.Name] {
			return nil, invalid("名前 %s が重なっています（AP とグループをまたいで一意にしてください）", a.Name)
		}
		seen[a.Name] = true
		out = append(out, db.AP{Name: a.Name, Kind: a.Kind, Purpose: a.Purpose, CertSerial: a.CertSerial, CertNotAfter: a.CertNotAfter})
	}
	return out, nil
}

// missingCRLs は反映に足りない CRL の表示の名前を返す。
func (s *Service) missingCRLs(ctx context.Context, t db.Tenant) ([]string, error) {
	var out []string
	crl, err := s.DB.CRL(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	if crl.PEM == "" {
		out = append(out, "CRL")
	}
	brought, err := s.DB.BroughtCAs(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	for _, b := range brought {
		if !b.HasCRL {
			continue
		}
		c, err := s.DB.CRLOf(ctx, t.ID, b.CAID)
		if err != nil {
			return nil, err
		}
		if c.PEM == "" {
			out = append(out, "持ち込みの CA "+b.CAID+" の CRL")
		}
	}
	return out, nil
}

// StartApply は反映を裏で始める（§24.11 の EA5）。テナントがない・停止している・証明書が足りないときは誤りを返す（足りない CRL は裏の処理の
// 最初に取りに行く）。すでに動いていれば、何もせずに started = false を返す（取り残した変更は中央の次の周回が拾う）。
func (s *Service) StartApply(ctx context.Context, a Actor, id string) (started bool, err error) {
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return false, err
	}
	if !t.Enabled {
		return false, invalidCause(CauseTenantStopped, "停止しているテナントは反映できません。起動してから反映してください")
	}
	missing, err := s.Missing(ctx, t)
	if err != nil {
		return false, err
	}
	crls, err := s.missingCRLs(ctx, t)
	if err != nil {
		return false, err
	}
	missing = slices.DeleteFunc(missing, func(m string) bool { return slices.Contains(crls, m) })
	if len(missing) > 0 {
		return false, invalidCause(CauseNotReady, "反映に要るものがそろっていません: %s", strings.Join(missing, "、"))
	}
	s.mu.Lock()
	if _, running := s.applying[id]; running {
		s.mu.Unlock()
		return false, nil
	}
	s.applying[id] = s.Now()
	s.mu.Unlock()
	// 要求のコンテキストは応答を返すと終わるので切り離す（トレースID は引き継ぐ）。SIGTERM（Shutdown）では取り消す。
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.ApplyTimeout)
	stop := context.AfterFunc(s.bgCtx, cancel)
	s.bgWG.Go(func() {
		defer func() {
			stop()
			cancel()
			s.mu.Lock()
			delete(s.applying, id)
			s.mu.Unlock()
		}()
		s.runApply(bg, a, t)
	})
	return true, nil
}

// runApply は裏の反映の中身。Apply が記録を残さずに終わったとき（排他を取れないなど）は、ここで失敗を記録する。
func (s *Service) runApply(ctx context.Context, a Actor, t db.Tenant) {
	if crls, err := s.missingCRLs(ctx, t); err == nil && len(crls) > 0 {
		if err := s.RefreshCRL(ctx, a, t.ID); err != nil {
			s.Log.Warn("cannot fetch the missing crl before apply", "tenant", t.ID, "error", err)
		}
	}
	rec, err := s.Apply(ctx, a, t.ID)
	if err != nil && rec.TenantID == "" && !errors.Is(err, db.ErrNotFound) {
		failed := db.Apply{TenantID: t.ID, Version: t.DesiredVersion, Revision: t.Revision, Trigger: db.TriggerApply, Result: db.ResultFailed,
			Error: err.Error(), Operator: a.Operator, Started: s.Now()}
		s.record(ctx, &failed)
	}
}

// ApplyRunning は、裏の反映が動いていれば始めた時刻を返す。
func (s *Service) ApplyRunning(id string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.applying[id]
	return at, ok
}

// Shutdown は裏の反映を取り消し（前の版に戻し始める）、終わるのを wait まで待つ（§24.11 の EA5）。待ちきれなくても、次の起動で前の版に戻す（EA6）。
func (s *Service) Shutdown(wait time.Duration) {
	s.bgCancel()
	done := make(chan struct{})
	go func() {
		s.bgWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		s.Log.Warn("background applies did not finish before shutdown")
	}
}

// statusCacheFor は agent の状態を使い回す時間（§24.11 の EA9）。
const statusCacheFor = 10 * time.Second

// AgentStatus は agent の状態を、statusCacheFor の間は使い回して返す（agent は呼ぶたびに全コンテナの詳しい状態を読むので、管理API の読み出しで何度も呼ばない）。
func (s *Service) AgentStatus(ctx context.Context) (agent.Status, error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if !s.statusAt.IsZero() && s.Now().Sub(s.statusAt) < statusCacheFor {
		return s.statusCache, nil
	}
	st, err := s.Agent.Status(ctx)
	if err != nil {
		return agent.Status{}, err
	}
	s.statusCache, s.statusAt = st, s.Now()
	return st, nil
}

// forgetStatus は agent の状態の写しを捨てる（コンテナを変えたとき。すぐ後の読み出しに古い状態を見せないように）。
func (s *Service) forgetStatus() {
	s.statusMu.Lock()
	s.statusAt = time.Time{}
	s.statusMu.Unlock()
}

// CRLReport は 1 つの CA の CRL の取得の結果（§24.11 の EA8）。
type CRLReport struct {
	CA db.CRL
	// CAID は表示の ID（発行した CA は tenant.<slug>）。
	CAID string
	// OK は CRL があり、最後の取得に失敗していないか。
	OK bool
}

// CRLReports はテナントの CA ごとの CRL の状態を返す。発行した CA が先頭。CRL のない持ち込みの CA は含めない。
func (s *Service) CRLReports(ctx context.Context, t db.Tenant) ([]CRLReport, error) {
	var out []CRLReport
	add := func(caID, label string) error {
		c, err := s.DB.CRLOf(ctx, t.ID, caID)
		if err != nil {
			return err
		}
		out = append(out, CRLReport{CA: c, CAID: label, OK: c.PEM != "" && c.LastError == ""})
		return nil
	}
	if err := add("", "tenant."+t.Slug); err != nil {
		return nil, err
	}
	brought, err := s.DB.BroughtCAs(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	for _, b := range brought {
		if b.HasCRL {
			if err := add(b.CAID, b.CAID); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// crlRefreshTimeout は管理API の CRL の取り直しの全体の上限（中継のタイムアウトより短くする。§24.11 の EA8）。
const crlRefreshTimeout = 25 * time.Second

// RefreshCRLReport は CRL をすぐ取りに行き、CA ごとの結果と、全体の誤りの文（なければ空）を返す（§24.11 の EA8）。テナントがない・排他を取れないときは誤りを返す。
func (s *Service) RefreshCRLReport(ctx context.Context, a Actor, id string) ([]CRLReport, string, error) {
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return nil, "", err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), crlRefreshTimeout)
	defer cancel()
	msg := ""
	if err := s.RefreshCRL(rctx, a, id); err != nil {
		if errors.Is(err, ErrBusy) || errors.Is(err, db.ErrNotFound) {
			return nil, "", err
		}
		msg = truncate(err.Error(), 2000)
	}
	reports, err := s.CRLReports(context.WithoutCancel(ctx), t)
	if err != nil {
		return nil, "", fmt.Errorf("crl reports: %w", err)
	}
	return reports, msg, nil
}
