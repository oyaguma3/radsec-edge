package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/diff"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// keepGenerations は残す版のディレクトリの数（今の版と直前の版を含む。§10.2）。
const keepGenerations = 3

// Missing は、反映に足りないもの（クライアントCA の証明書・CRL・持ち込みの CA の CRL・サーバー証明書・ヘルスチェック用の証明書）を返す（§11.3）。
// 空なら反映できる（中身の誤りは生成のときに確かめる）。
func (s *Service) Missing(ctx context.Context, t db.Tenant) ([]string, error) {
	var out []string
	if t.ClientCAPEM == "" {
		out = append(out, "クライアントCA の証明書")
	}
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
	for _, k := range []struct {
		kind  keystore.Kind
		cert  string
		label string
	}{{keystore.Server, t.ServerCertPEM, "サーバー証明書"}, {keystore.Probe, t.ProbeCertPEM, "ヘルスチェック用の証明書"}} {
		key, err := s.Keys.Current(t.ID, k.kind)
		if err != nil {
			return nil, err
		}
		if k.cert == "" || key == nil {
			out = append(out, k.label)
		}
	}
	return out, nil
}

// render はテナントの望む状態からバンドルを生成する。
func (s *Service) render(ctx context.Context, t db.Tenant) (rsconf.Bundle, error) {
	missing, err := s.Missing(ctx, t)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, invalid("反映に要るものがそろっていません: %s", strings.Join(missing, "、"))
	}
	aps, err := s.DB.APs(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	crl, err := s.DB.CRL(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	// ヘルスチェック用の証明書が今のクライアントCA で検証できなければ、反映してもヘルスチェックが通らず、その間 AP の接続が
	// 途切れるので、反映の前に断る。失効していれば、出し直すまで反映を断る（設計概要 §11.2、§11.3、§22.4）。
	if err := s.checkProbeCert(t, []byte(crl.PEM)); err != nil {
		return nil, invalid("%v", err)
	}
	key, err := s.Keys.Current(t.ID, keystore.Server)
	if err != nil {
		return nil, err
	}
	in := rsconf.Input{Slug: t.Slug, TenantID: t.ID, URNPrefix: s.URNPrefix, Stamp: s.Stamp, Auth: t.AuthUpstream, Acct: t.AcctUpstream, Secret: s.Secret,
		ClientCAPEM: []byte(t.ClientCAPEM), CRLPEM: []byte(crl.PEM), ServerCertPEM: []byte(t.ServerCertPEM), ServerKeyPEM: key, Now: s.Now(),
		SourceCIDRs: t.SourceCIDRs, SharedMatch: rsconf.Match{Attr: t.SharedMatchAttr, Pattern: t.SharedMatchPattern}}
	for _, a := range aps {
		if a.Kind == db.KindGroup {
			in.Groups = append(in.Groups, a.Name)
		} else {
			in.APs = append(in.APs, a.Name)
		}
	}
	brought, err := s.DB.BroughtCAs(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	for _, b := range brought {
		c, err := s.DB.CRLOf(ctx, t.ID, b.CAID)
		if err != nil {
			return nil, err
		}
		// 持ち込みの CA の CRL が切れていても反映は止めない（その CA の AP だけが拒否される。§24.5）。警告だけを出す。
		if c.PEM != "" && !c.NextUpdate.IsZero() && !s.Now().Before(c.NextUpdate) {
			s.Log.Warn("the CRL of a brought CA has expired; only the APs of that CA are rejected", "tenant", t.ID, "ca", b.CAID, "next_update", c.NextUpdate)
		}
		in.Brought = append(in.Brought, rsconf.BroughtCA{ID: b.CAID, CertPEM: []byte(b.CertPEM), CRLPEM: []byte(c.PEM), HasCRL: b.HasCRL})
	}
	if len(t.SourceCIDRs) > 0 {
		st, err := s.Agent.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("agent: %w", err)
		}
		for _, n := range st.NetworkSubnets {
			p, err := netip.ParsePrefix(n)
			if err != nil {
				return nil, fmt.Errorf("network subnet %q: %w", n, err)
			}
			in.ProbeCIDRs = append(in.ProbeCIDRs, p)
		}
	}
	b, err := rsconf.Render(in)
	if err != nil {
		return nil, invalid("設定を生成できません: %v", err)
	}
	return b, nil
}

// Plan は、反映したときに変わること（画面の「未反映の変更」。§11.1）。
type Plan struct {
	// Missing は反映に足りないもの、Error は設定を生成できない理由（どちらかがあれば反映できない）。
	Missing []string
	Error   string
	// Hunks は radsecproxy.conf の差分、Files は設定のほかに変わるファイル（CA と CRL、サーバー証明書）。
	Hunks []diff.Hunk
	Files []string
	// Action は反映のときに radsecproxy に行う操作。Same は反映済みの版と同じか。
	Action rsconf.Action
	Same   bool
}

// Ready は反映できるか。
func (p Plan) Ready() bool { return len(p.Missing) == 0 && p.Error == "" }

// Plan は、反映済みの版と、今の望む状態から生成した版の違いを返す。
func (s *Service) Plan(ctx context.Context, id string) (Plan, error) {
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if p.Missing, err = s.Missing(ctx, t); err != nil {
		return Plan{}, err
	}
	if len(p.Missing) > 0 {
		return p, nil
	}
	b, err := s.render(ctx, t)
	if err != nil {
		if IsInput(err) {
			p.Error = err.Error()
			return p, nil
		}
		return Plan{}, err
	}
	_, old, err := s.Store.Current(t.Slug)
	if err != nil {
		return Plan{}, err
	}
	p.Action = b.ActionFrom(old)
	p.Same = old != nil && old.Hash() == b.Hash()
	p.Hunks = diff.Hunks(diff.Lines(string(old[rsconf.FileConf]), string(b[rsconf.FileConf])), 3)
	if old != nil {
		if string(old[rsconf.FileCABundle]) != string(b[rsconf.FileCABundle]) {
			p.Files = append(p.Files, "クライアントCA の証明書と CRL")
		}
		if string(old[rsconf.FileServerCert]) != string(b[rsconf.FileServerCert]) || string(old[rsconf.FileServerKey]) != string(b[rsconf.FileServerKey]) {
			p.Files = append(p.Files, "サーバー証明書")
		}
	}
	return p, nil
}

// record は反映の記録を書く。
func (s *Service) record(ctx context.Context, a *db.Apply) {
	a.Finished = s.Now()
	a.Error = truncate(a.Error, 4000)
	if err := s.DB.InsertApply(context.WithoutCancel(ctx), *a); err != nil {
		s.Log.Error("cannot write apply record", "tenant", a.TenantID, "error", err)
	}
	level := s.Log.Info
	if a.Result != db.ResultOK {
		level = s.Log.Warn
	}
	level("apply", "tenant", a.TenantID, "version", a.Version, "trigger", a.Trigger, "action", a.Action, "result", a.Result, "error", a.Error)
}

// Apply はテナントの望む状態を反映する（§11.1）。生成 → 版のディレクトリに書いて構文検査 → current を付け替え →
// SIGHUP か再起動 → ヘルスチェック → 失敗したら前の版に戻す。結果は反映の記録に残し、返す。
// 反映できなかったとき（前の版のまま、または前の版に戻したとき）は、記録とともにエラーを返す。
func (s *Service) Apply(ctx context.Context, a Actor, id string) (db.Apply, error) {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return db.Apply{}, err
	}
	if !t.Enabled {
		return db.Apply{}, invalid("停止しているテナントは反映できません。起動してから反映してください")
	}
	rec := db.Apply{TenantID: id, Version: t.DesiredVersion, Trigger: db.TriggerApply, Operator: a.Operator, Started: s.Now()}
	fail := func(result string, err error) (db.Apply, error) {
		rec.Result, rec.Error = result, err.Error()
		s.record(ctx, &rec)
		s.audit(ctx, a, "tenant.apply", id, map[string]any{"version": rec.Version, "result": rec.Result})
		return rec, err
	}

	b, err := s.render(ctx, t)
	if err != nil {
		return fail(db.ResultFailed, err)
	}
	rec.Hash = b.Hash()
	oldGen, old, err := s.Store.Current(t.Slug)
	if err != nil {
		return fail(db.ResultFailed, err)
	}
	gen, err := s.Store.Stage(t.Slug, b)
	if err != nil {
		return fail(db.ResultFailed, err)
	}
	if gen != oldGen {
		res, err := s.Agent.Validate(ctx, t.Slug, gen)
		if err != nil {
			return fail(db.ResultFailed, fmt.Errorf("構文検査ができません: %w", err))
		}
		if !res.OK {
			return fail(db.ResultFailed, fmt.Errorf("radsecproxy の構文検査で誤りが見つかりました:\n%s", strings.TrimSpace(res.Output)))
		}
		if err := s.Store.Activate(t.Slug, gen); err != nil {
			return fail(db.ResultFailed, err)
		}
	}
	rec.Action, err = s.bring(ctx, t, t.Port, b.ActionFrom(old))
	if err == nil {
		err = s.probeUntil(ctx, t, t.Port)
	}
	if err != nil {
		// 前の版に戻す（前の版がなければ止めて、current を外す。整合ループが壊れた版で起動しないように）。
		if rerr := s.rollback(ctx, t, oldGen); rerr != nil {
			err = fmt.Errorf("%w（前の版に戻すのにも失敗しました: %v）", err, rerr)
		}
		return fail(db.ResultRolledBack, err)
	}
	if err := s.DB.MarkApplied(ctx, id, t.DesiredVersion, b.Hash(), t.Port); err != nil {
		return fail(db.ResultFailed, err)
	}
	if err := s.Store.Prune(t.Slug, keepGenerations); err != nil {
		s.Log.Warn("cannot remove old generations", "tenant", id, "error", err)
	}
	rec.Result = db.ResultOK
	s.record(ctx, &rec)
	s.audit(ctx, a, "tenant.apply", id, map[string]any{"version": rec.Version, "result": rec.Result, "action": rec.Action})
	return rec, nil
}

// bring は、コンテナを作る・起動する（Ensure）。動いていたコンテナには、want（SIGHUP か再起動）を行う。行ったことを返す。
func (s *Service) bring(ctx context.Context, t db.Tenant, port int, want rsconf.Action) (string, error) {
	action, err := s.Agent.Ensure(ctx, t.ID, t.Slug, port)
	if err != nil {
		return "ensure", err
	}
	if action != agent.EnsureNone {
		return action, nil // 作った・起動したコンテナは、新しい版を読んでいる
	}
	switch want {
	case rsconf.ActionRestart:
		return "restart", s.Agent.Restart(ctx, t.ID)
	case rsconf.ActionSIGHUP:
		return "sighup", s.Agent.SIGHUP(ctx, t.ID)
	}
	return "none", nil
}

// rollback は前の版 oldGen に戻して再起動する。前の版がなければ、コンテナを止めて current を外す。
func (s *Service) rollback(ctx context.Context, t db.Tenant, oldGen string) error {
	ctx = context.WithoutCancel(ctx)
	if oldGen == "" {
		err := s.Agent.Stop(ctx, t.ID)
		if errors.Is(err, agent.ErrNotFound) {
			err = nil
		}
		return errors.Join(err, s.Store.Deactivate(t.Slug))
	}
	if err := s.Store.Activate(t.Slug, oldGen); err != nil {
		return err
	}
	port := t.AppliedPort
	if port == 0 {
		port = t.Port
	}
	action, err := s.Agent.Ensure(ctx, t.ID, t.Slug, port)
	if err != nil {
		return err
	}
	if action == agent.EnsureNone {
		if err := s.Agent.Restart(ctx, t.ID); err != nil {
			return err
		}
	}
	crl, err := s.DB.CRL(ctx, t.ID)
	if err != nil {
		return err
	}
	if err := s.healthCheck(ctx, t, port, []byte(crl.PEM)); err != nil {
		return fmt.Errorf("前の版のヘルスチェック: %w", err)
	}
	return nil
}

// probeUntil は、ヘルスチェックが通るまで ProbeTimeout の間くり返す（起動の直後は、まだ待ち受けていない）。
func (s *Service) probeUntil(ctx context.Context, t db.Tenant, port int) error {
	key, err := s.Keys.Current(t.ID, keystore.Probe)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(t.ProbeCertPEM), key)
	if err != nil {
		return fmt.Errorf("ヘルスチェック用の証明書: %w", err)
	}
	srv, err := pki.ParseCert([]byte(t.ServerCertPEM))
	if err != nil {
		return fmt.Errorf("サーバー証明書: %w", err)
	}
	addr := s.ProbeAddr(t.Slug, port)
	ctx, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
	defer cancel()
	var last error
	for {
		tctx, tcancel := context.WithTimeout(ctx, 3*time.Second)
		last = s.Probe(tctx, addr, cert, srv)
		tcancel()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ヘルスチェックが通りません（%s）: %w", addr, last)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// syncTenant は、1 つのテナントのコンテナを望む運用の状態に戻す（§11.5）。未反映の変更は反映しない。
// 停止したテナントのコンテナは止め、起動しているテナントで反映済みの版があれば、コンテナを作る・起動する。
// 呼び出し側でテナントの排他を取る。
func (s *Service) syncTenant(ctx context.Context, t db.Tenant, st agent.Status, a Actor) error {
	c, exists := st.Container(t.ID)
	rec := db.Apply{TenantID: t.ID, Version: t.AppliedVersion, Hash: t.AppliedHash, Trigger: db.TriggerReconcile, Operator: a.Operator, Started: s.Now()}
	if !t.Enabled {
		if !exists || (!c.Running && !c.Restarting) {
			return nil
		}
		rec.Action = "stop"
		if err := s.Agent.Stop(ctx, t.ID); err != nil {
			rec.Result, rec.Error = db.ResultFailed, err.Error()
			s.record(ctx, &rec)
			return err
		}
		rec.Result = db.ResultOK
		s.record(ctx, &rec)
		return nil
	}
	gen, _, err := s.Store.Current(t.Slug)
	if err != nil {
		return err
	}
	if gen == "" {
		return nil // まだ反映していない
	}
	port := t.AppliedPort
	if port == 0 {
		port = t.Port
	}
	// 再起動の途中（Docker が再起動の方針で起動し直している）のコンテナには触れない。
	if exists && (c.Running || c.Restarting) && c.SpecCurrent && c.Port == port {
		return nil
	}
	rec.Action, err = s.Agent.Ensure(ctx, t.ID, t.Slug, port)
	if err == nil && rec.Action == agent.EnsureNone {
		return nil
	}
	if err == nil {
		var crl db.CRL
		if crl, err = s.DB.CRL(ctx, t.ID); err == nil {
			err = s.healthCheck(ctx, t, port, []byte(crl.PEM))
		}
	}
	if err != nil {
		rec.Result, rec.Error = db.ResultFailed, err.Error()
		s.record(ctx, &rec)
		return err
	}
	rec.Result = db.ResultOK
	s.record(ctx, &rec)
	return nil
}

// Reconcile は、すべてのテナントのコンテナを望む運用の状態に戻し、消したテナントのコンテナとディレクトリを片付ける（§11.5）。
func (s *Service) Reconcile(ctx context.Context) error {
	err := s.reconcile(ctx)
	s.mu.Lock()
	s.lastReconcile = ReconcileState{At: s.Now()}
	if err != nil {
		s.lastReconcile.Error = err.Error()
	}
	s.mu.Unlock()
	return err
}

func (s *Service) reconcile(ctx context.Context) error {
	st, err := s.Agent.Status(ctx)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	if !st.DockerOK {
		return fmt.Errorf("agent cannot reach Docker: %s", st.DockerError)
	}
	tenants, err := s.DB.Tenants(ctx)
	if err != nil {
		return err
	}
	ids, slugs := map[string]bool{}, map[string]bool{}
	var errs []error
	for _, t := range tenants {
		ids[t.ID], slugs[t.Slug] = true, true
		unlock := s.lock(t.ID)
		// 排他を待つ間に変わっているかもしれないので、読み直す。
		if cur, err := s.DB.Tenant(ctx, t.ID); err == nil {
			if err := s.syncTenant(ctx, cur, st, System); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", t.ID, err))
			}
		}
		unlock()
	}
	for _, c := range st.Containers {
		if ids[c.TenantID] || !names.ValidSlug(c.TenantID) {
			continue
		}
		unlock := s.lock(c.TenantID)
		if _, err := s.DB.Tenant(ctx, c.TenantID); errors.Is(err, db.ErrNotFound) {
			if err := s.Agent.Remove(ctx, c.TenantID); err != nil && !errors.Is(err, agent.ErrNotFound) {
				errs = append(errs, err)
			} else {
				s.audit(ctx, System, "container.remove_orphan", c.TenantID, map[string]any{"container": c.Name})
			}
		}
		unlock()
	}
	onDisk, err := s.Store.Slugs()
	if err != nil {
		errs = append(errs, err)
	}
	for _, slug := range onDisk {
		if !slugs[slug] {
			if _, err := s.DB.Tenant(ctx, slug); errors.Is(err, db.ErrNotFound) {
				errs = append(errs, s.Store.Remove(slug))
			}
		}
	}
	return errors.Join(errs...)
}

// LastReconcile は最後の整合ループの結果を返す。
func (s *Service) LastReconcile() ReconcileState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReconcile
}

// Run は整合ループと AP の最後の接続の読み取り（interval ごと）と CRL の取得（crlInterval ごと）を、ctx が終わるまで動かす。
// 起動したときにも 1 回ずつ行う。
func (s *Service) Run(ctx context.Context, interval, crlInterval time.Duration) {
	go func() {
		for {
			s.RefreshAllCRLs(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(crlInterval):
			}
		}
	}()
	for {
		if err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
			s.Log.Warn("reconcile", "error", err)
		}
		if err := s.RefreshLastSeen(ctx); err != nil && ctx.Err() == nil {
			s.Log.Warn("refresh last seen", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
