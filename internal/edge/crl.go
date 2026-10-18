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

// maxCRLBytes は取得する CRL の大きさの上限。
const maxCRLBytes = 4 << 20

// CRLURL はテナントの CRL の取得先を返す（テナントごとの値、なければ EDGE_CRL_BASE_URL + /crl/tenant.<slug>.pem。§9.5）。
// どちらもなければ空。
func (s *Service) CRLURL(t db.Tenant) string {
	if t.CRLURL != "" {
		return t.CRLURL
	}
	if s.CRLBaseURL == "" {
		return ""
	}
	return s.CRLBaseURL + "/crl/tenant." + t.Slug + ".pem"
}

// RefreshAllCRLs は、クライアントCA の証明書と取得先のあるテナントの CRL を取りに行く（定期の処理）。
func (s *Service) RefreshAllCRLs(ctx context.Context) {
	tenants, err := s.DB.Tenants(ctx)
	if err != nil {
		s.Log.Error("refresh crls", "error", err)
		return
	}
	for _, t := range tenants {
		if t.ClientCAPEM == "" || s.CRLURL(t) == "" {
			continue
		}
		if err := s.RefreshCRL(ctx, System, t.ID); err != nil && ctx.Err() == nil {
			s.Log.Warn("cannot refresh crl", "tenant", t.ID, "url", s.CRLURL(t), "error", err)
		}
	}
}

// RefreshCRL はテナントの CRL を CA から取りに行き、変わっていれば検証して置き、反映済みの版に入れて SIGHUP を送る。
// 変わっていなければ（304）何もしない。
func (s *Service) RefreshCRL(ctx context.Context, a Actor, id string) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if t.ClientCAPEM == "" {
		return invalid("先にクライアントCA の証明書を取り込んでください")
	}
	url := s.CRLURL(t)
	if url == "" {
		return invalid("CRL の取得先がありません（テナントの CRL の取得先か、EDGE_CRL_BASE_URL を設定してください）")
	}
	cur, err := s.DB.CRL(ctx, id)
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
	return s.install(ctx, a, t, cur, body, "fetch", etag)
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
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("CRL を取得できません: %w", err)
	}
	if len(body) > maxCRLBytes {
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
	return s.install(ctx, a, t, cur, pemData, "upload", "")
}

// install は CRL を検証して DB に置き、反映済みの版に入れる。クライアントCA の署名でない、期限が切れている、
// 番号が今の CRL より小さいものは置かない（期限の切れた CRL を置いて SIGHUP すると全接続が切れる。§9.5、§11.2）。
// 呼び出し側でテナントの排他を取る。
func (s *Service) install(ctx context.Context, a Actor, t db.Tenant, cur db.CRL, data []byte, source, etag string) error {
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
	ca, err := pki.ParseCert([]byte(t.ClientCAPEM))
	if err != nil {
		return err
	}
	crl, err := pki.ParseCRL(data)
	if err != nil {
		return reject(err)
	}
	var prev *big.Int
	if cur.PEM != "" {
		if n, ok := new(big.Int).SetString(cur.Number, 10); ok {
			prev = n
		}
	}
	info, err := pki.CheckCRL(crl, ca, prev, now)
	if err != nil {
		return reject(err)
	}
	newPEM := string(pki.EncodeCRL(crl.Raw))
	changed := newPEM != cur.PEM
	if changed {
		cur.PEM, cur.Number, cur.ThisUpdate, cur.NextUpdate = newPEM, info.Number.String(), info.ThisUpdate, info.NextUpdate
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
	s.audit(ctx, a, "crl.install", t.ID, map[string]any{"source": source, "number": cur.Number, "revoked": info.Revoked,
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
			err = s.healthCheck(ctx, t, port, crlPEM)
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
