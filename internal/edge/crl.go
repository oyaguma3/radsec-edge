package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// CRLURL はテナントの発行した CA の CRL の取得先を返す（テナントごとの値、なければ EDGE_CRL_BASE_URL + /crl/tenant.<slug>.pem。§9.5）。
// どちらもなければ空。
func (s *Service) CRLURL(t db.Tenant) string {
	if t.CRLURL != "" {
		return t.CRLURL
	}
	return s.crlURLOf("tenant." + t.Slug)
}

// crlURLOf は CA の ID の CRL の取得先（EDGE_CRL_BASE_URL + /crl/<CA の ID>.pem。§24.6）。EDGE_CRL_BASE_URL がなければ空。
func (s *Service) crlURLOf(caID string) string {
	if s.CRLBaseURL == "" {
		return ""
	}
	return s.CRLBaseURL + "/crl/" + caID + ".pem"
}

// RefreshAllCRLs は、すべてのテナントの CRL を取りに行く（定期の処理）。
func (s *Service) RefreshAllCRLs(ctx context.Context) {
	tenants, err := s.DB.Tenants(ctx)
	if err != nil {
		s.Log.Error("refresh crls", "error", err)
		return
	}
	for _, t := range tenants {
		if t.ClientCAPEM == "" {
			continue
		}
		if err := s.refreshTenantCRLs(ctx, System, t.ID, true); err != nil && ctx.Err() == nil {
			s.Log.Warn("cannot refresh crl", "tenant", t.ID, "error", err)
		}
	}
}

// RefreshCRL はテナントの CRL（発行した CA と、CRL のある持ち込みの CA のそれぞれ）を CA から取りに行き、変わっていれば検証して置き、
// 反映済みの版に入れて SIGHUP を送る。変わっていなければ（304）何もしない。1 つの CA で失敗しても、ほかの CA は続ける
// （こちらの失効の反映を止めないため。§24.5）。
func (s *Service) RefreshCRL(ctx context.Context, a Actor, id string) error {
	return s.refreshTenantCRLs(ctx, a, id, false)
}

func (s *Service) refreshTenantCRLs(ctx context.Context, a Actor, id string, skipNoURL bool) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if t.ClientCAPEM == "" {
		return invalid("先にクライアントCA の証明書を取り込んでください")
	}
	url := s.CRLURL(t)
	if url == "" && !skipNoURL {
		return invalid("CRL の取得先がありません（テナントの CRL の取得先か、EDGE_CRL_BASE_URL を設定してください）")
	}
	var errs []error
	if url != "" {
		errs = append(errs, s.refreshOne(ctx, a, t, "", []byte(t.ClientCAPEM), url))
	}
	brought, err := s.DB.BroughtCAs(ctx, id)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, b := range brought {
		if !b.HasCRL {
			continue
		}
		u := s.crlURLOf(b.CAID)
		if u == "" {
			errs = append(errs, invalid("持ち込みの CA %s の CRL の取得先がありません（EDGE_CRL_BASE_URL を設定してください）", b.CAID))
			continue
		}
		errs = append(errs, s.refreshOne(ctx, a, t, b.CAID, []byte(b.CertPEM), u))
	}
	return errors.Join(errs...)
}

// refreshOne は 1 つの CA の CRL を取りに行く。呼び出し側でテナントの排他を取る。
func (s *Service) refreshOne(ctx context.Context, a Actor, t db.Tenant, caID string, caPEM []byte, url string) error {
	cur, err := s.DB.CRLOf(ctx, t.ID, caID)
	if err != nil {
		return err
	}
	cur.LastAttemptAt = s.Now()
	body, etag, notModified, err := s.fetch(ctx, url, cur)
	if err == nil && notModified {
		cur.LastSuccessAt, cur.LastError = s.Now(), ""
		if err := s.DB.PutCRL(ctx, cur); err != nil {
			return err
		}
		if cur.PEM == "" {
			return nil
		}
		// 前に反映済みの版に入れられなかった CRL があれば、入れ直す（同じなら何もしない）。
		return s.pushCRL(ctx, t, []byte(cur.PEM))
	}
	if err != nil {
		cur.LastError = err.Error()
		return errors.Join(err, s.DB.PutCRL(ctx, cur))
	}
	return s.install(ctx, a, t, caPEM, cur, body, "fetch", etag)
}

// fetch は CRL を取得する。前に置いた CRL があれば If-None-Match を付ける（変わっていなければ 304）。
func (s *Service) fetch(ctx context.Context, url string, cur db.CRL) (body []byte, etag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}
	if cur.PEM != "" && cur.ETag != "" {
		req.Header.Set("If-None-Match", cur.ETag)
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("CRL を取得できません: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, "", true, nil
	case http.StatusOK:
	default:
		return nil, "", false, fmt.Errorf("CRL を取得できません: %s %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, pki.MaxCRLBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("CRL を取得できません: %w", err)
	}
	if len(body) > pki.MaxCRLBytes {
		return nil, "", false, errors.New("CRL が大きすぎます")
	}
	return body, resp.Header.Get("ETag"), false, nil
}

// InstallCRL は、画面から貼り付けた CRL を取り込む（取得と同じ検証をして、反映済みの版に入れる。§9.5）。
func (s *Service) InstallCRL(ctx context.Context, a Actor, id string, pemData []byte) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if t.ClientCAPEM == "" {
		return invalid("先にクライアントCA の証明書を取り込んでください")
	}
	cur, err := s.DB.CRL(ctx, id)
	if err != nil {
		return err
	}
	return s.install(ctx, a, t, []byte(t.ClientCAPEM), cur, pemData, "upload", "")
}

// InstallBroughtCRL は持ち込みの CA の CRL を取り込む（取得と同じ検証をして、反映済みの版に入れる）。
func (s *Service) InstallBroughtCRL(ctx context.Context, a Actor, id, caID string, pemData []byte) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	brought, err := s.DB.BroughtCAs(ctx, id)
	if err != nil {
		return err
	}
	for _, b := range brought {
		if b.CAID != caID {
			continue
		}
		if !b.HasCRL {
			return invalid("持ち込みの CA %s に CRL はありません", caID)
		}
		cur, err := s.DB.CRLOf(ctx, id, caID)
		if err != nil {
			return err
		}
		return s.install(ctx, a, t, []byte(b.CertPEM), cur, pemData, "upload", "")
	}
	return invalid("持ち込みの CA %s はありません", caID)
}

// install は CRL を検証して DB に置き、反映済みの版に入れる。caPEM の CA の署名でない、期限が切れている、今の CRL より古いものは
// 置かない（期限の切れた CRL を置いて SIGHUP すると、その CA の接続が切れる。§9.5、§11.2）。呼び出し側でテナントの排他を取る。
func (s *Service) install(ctx context.Context, a Actor, t db.Tenant, caPEM []byte, cur db.CRL, data []byte, source, etag string) error {
	now := s.Now()
	cur.LastAttemptAt = now
	reject := func(err error) error {
		if source == "fetch" {
			cur.LastError = err.Error()
			if perr := s.DB.PutCRL(ctx, cur); perr != nil {
				return errors.Join(err, perr)
			}
		}
		return invalid("CRL を置けません: %v", err)
	}
	ca, err := pki.ParseCert(caPEM)
	if err != nil {
		return err
	}
	crl, err := pki.ParseCRL(data)
	if err != nil {
		return reject(err)
	}
	var prev pki.Previous
	if cur.PEM != "" {
		prev.ThisUpdate = cur.ThisUpdate
		if n, ok := new(big.Int).SetString(cur.Number, 10); ok {
			prev.Number = n
		}
	}
	info, err := pki.CheckCRL(crl, ca, prev, now)
	if err != nil {
		return reject(err)
	}
	newPEM := string(pki.EncodeCRL(crl.Raw))
	changed := newPEM != cur.PEM
	if changed {
		number := ""
		if info.Number != nil {
			number = info.Number.String()
		}
		cur.PEM, cur.Number, cur.ThisUpdate, cur.NextUpdate = newPEM, number, info.ThisUpdate, info.NextUpdate
		cur.Source, cur.InstalledAt = source, now
	}
	cur.LastSuccessAt, cur.LastError = now, ""
	if etag != "" || source == "upload" {
		cur.ETag = etag
	}
	if err := s.DB.PutCRL(ctx, cur); err != nil {
		return err
	}
	if !changed {
		return nil
	}
	s.audit(ctx, a, "crl.install", t.ID, map[string]any{"source": source, "ca": cur.CAID, "number": cur.Number, "revoked": info.Revoked,
		"next_update": info.NextUpdate.UTC().Format("2006-01-02T15:04:05Z")})
	return s.pushCRL(ctx, t, []byte(newPEM))
}

// pushCRL は、反映済みの版を写して CRL だけを入れ替えた版を作り、current を付け替えて SIGHUP を送る（§9.5。
// 望む状態の版は上げない）。ヘルスチェックが通らなければ前の版に戻す。反映済みの版がなければ何もしない
// （次の反映で入る）。
func (s *Service) pushCRL(ctx context.Context, t db.Tenant, crlPEM []byte) error {
	oldGen, old, err := s.Store.Current(t.Slug)
	if err != nil || oldGen == "" {
		return err
	}
	b, err := old.WithCRL(crlPEM, s.Now())
	if err != nil {
		// 反映済みの版の CA と違う（CA を取り込んで、まだ反映していない）など。次の反映で入る。
		s.Log.Warn("crl is not pushed to the applied generation", "tenant", t.ID, "error", err)
		return nil
	}
	if b.Hash() == old.Hash() {
		return nil
	}
	// 発行した CA の CRL が切れていれば読み込ませない（こちらの AP の接続が切れ、ヘルスチェックも通らない。§11.2）。
	// 持ち込みの CA の CRL が切れていても読み込ませる（その CA の AP だけが切れる。こちらの失効の反映を優先する。§24.5）。
	expired, err := b.IssuedCRLExpired(s.Now())
	if err != nil {
		return err
	}
	if expired {
		s.Log.Warn("the CRL of the issued CA has expired; the new CRL is not pushed until it is renewed", "tenant", t.ID)
		return nil
	}
	rec := db.Apply{TenantID: t.ID, Version: t.AppliedVersion, Hash: b.Hash(), Trigger: db.TriggerCRL, Action: "sighup",
		Operator: System.Operator, Started: s.Now()}
	gen, err := s.Store.Stage(t.Slug, b)
	if err == nil {
		err = s.Store.Activate(t.Slug, gen)
	}
	if err != nil {
		rec.Result, rec.Error = db.ResultFailed, err.Error()
		s.record(ctx, &rec)
		return err
	}
	port := t.AppliedPort
	if port == 0 {
		port = t.Port
	}
	// 停止しているテナントは、版を入れ替えるだけにする（起動したときに新しい CRL を読む）。
	if t.Enabled {
		err = s.Agent.SIGHUP(ctx, t.ID)
		if err == nil {
			// ヘルスチェック用の証明書を失効させた CRL でも、戻さずに置く（失効を優先する。§11.3）。
			var issued db.CRL
			if issued, err = s.DB.CRL(ctx, t.ID); err == nil {
				err = s.healthCheck(ctx, t, port, []byte(issued.PEM))
			}
		}
		if err != nil {
			rerr := s.Store.Activate(t.Slug, oldGen)
			if rerr == nil {
				rerr = s.Agent.SIGHUP(context.WithoutCancel(ctx), t.ID)
			}
			if rerr != nil {
				err = fmt.Errorf("%w（前の版に戻すのにも失敗しました: %v）", err, rerr)
			}
			rec.Result, rec.Error = db.ResultRolledBack, err.Error()
			s.record(ctx, &rec)
			return err
		}
	} else {
		rec.Action = "none"
	}
	if err := s.DB.MarkApplied(ctx, t.ID, t.AppliedVersion, b.Hash(), port); err != nil {
		return err
	}
	if err := s.Store.Prune(t.Slug, keepGenerations); err != nil {
		s.Log.Warn("cannot remove old generations", "tenant", t.ID, "error", err)
	}
	rec.Result = db.ResultOK
	s.record(ctx, &rec)
	return nil
}
