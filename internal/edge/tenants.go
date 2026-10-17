package edge

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// TenantInput はテナントを作る・変えるときの値。
type TenantInput struct {
	// Slug はテナントの名前（作るときだけ。変えない）。
	Slug string
	// Port は 0 なら空いているものを割り当てる。
	Port int
	// Auth と Acct は上流の認証と課金。
	Auth, Acct netip.AddrPort
	// CRLURL は CRL の取得先（空なら EDGE_CRL_BASE_URL から決める）。
	CRLURL string
}

func checkCRLURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return invalid("CRL の取得先は http(s) の URL（例 http://10.0.0.1:8449/crl/tenant.tenant-a.pem）にしてください")
	}
	return nil
}

func checkTenantInput(in TenantInput) error {
	if in.Port != 0 && (in.Port < config.PortMin || in.Port > config.PortMax) {
		return invalid("ポートは %d〜%d にしてください", config.PortMin, config.PortMax)
	}
	for _, u := range []netip.AddrPort{in.Auth, in.Acct} {
		if !u.IsValid() || u.Port() == 0 || u.Addr().IsUnspecified() {
			return invalid("上流は IP アドレスとポート（例 10.0.0.10:1812）で与えてください（ホスト名は使えません）")
		}
	}
	return checkCRLURL(in.CRLURL)
}

// conflict は DB の一意の制約の誤りを、利用者に見せる文にする。
func conflict(err error, msg string) error {
	if errors.Is(err, db.ErrConflict) {
		return invalid("%s（%v）", msg, err)
	}
	return err
}

// CreateTenant はテナントを作る（単独モードでは ID は slug と同じ。§21.2 の 4）。
func (s *Service) CreateTenant(ctx context.Context, a Actor, in TenantInput) (db.Tenant, error) {
	if err := names.CheckTenant(in.Slug); err != nil {
		return db.Tenant{}, invalid("テナントの名前は、%v", err)
	}
	if err := checkTenantInput(in); err != nil {
		return db.Tenant{}, err
	}
	if in.Port == 0 {
		p, err := s.DB.FreePort(ctx, config.PortMin, config.PortMax)
		if err != nil {
			return db.Tenant{}, conflict(err, "空いているポートがありません")
		}
		in.Port = p
	}
	t, err := s.DB.CreateTenant(ctx, db.TenantSpec{ID: in.Slug, Slug: in.Slug, Port: in.Port, AuthUpstream: in.Auth, AcctUpstream: in.Acct, CRLURL: in.CRLURL})
	if err != nil {
		return db.Tenant{}, conflict(err, "テナントの名前かポートが、ほかのテナントと重なっています")
	}
	s.audit(ctx, a, "tenant.create", t.ID, map[string]any{"slug": t.Slug, "port": t.Port,
		"auth_upstream": t.AuthUpstream.String(), "acct_upstream": t.AcctUpstream.String(), "crl_url": t.CRLURL})
	return t, nil
}

// UpdateTenant はテナントのポート・上流・CRL の取得先を変える（反映するまで radsecproxy には効かない）。
func (s *Service) UpdateTenant(ctx context.Context, a Actor, id string, in TenantInput) (db.Tenant, error) {
	if in.Port == 0 {
		return db.Tenant{}, invalid("ポートを入れてください")
	}
	if err := checkTenantInput(in); err != nil {
		return db.Tenant{}, err
	}
	t, err := s.DB.UpdateTenant(ctx, id, func(t *db.Tenant) error {
		t.Port, t.AuthUpstream, t.AcctUpstream, t.CRLURL = in.Port, in.Auth, in.Acct, in.CRLURL
		return nil
	})
	if err != nil {
		return db.Tenant{}, conflict(err, "ポートが、ほかのテナントと重なっています")
	}
	s.audit(ctx, a, "tenant.update", id, map[string]any{"port": t.Port, "auth_upstream": t.AuthUpstream.String(),
		"acct_upstream": t.AcctUpstream.String(), "crl_url": t.CRLURL})
	return t, nil
}

// DeleteTenant はテナントを消す（コンテナを消し、設定のディレクトリと鍵も消す）。
func (s *Service) DeleteTenant(ctx context.Context, a Actor, id string) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Agent.Remove(ctx, id); err != nil && !errors.Is(err, agent.ErrNotFound) {
		return err
	}
	if err := s.DB.DeleteTenant(ctx, id); err != nil {
		return err
	}
	var errs []error
	errs = append(errs, s.Store.Remove(t.Slug), s.Keys.Remove(id))
	s.audit(ctx, a, "tenant.delete", id, map[string]any{"slug": t.Slug, "port": t.Port})
	return errors.Join(errs...)
}

// SetEnabled はテナントを起動・停止する（運用の操作。望む状態の版は変えない）。すぐにコンテナに効かせる。
func (s *Service) SetEnabled(ctx context.Context, a Actor, id string, enabled bool) error {
	defer s.lock(id)()
	if err := s.DB.SetEnabled(ctx, id, enabled); err != nil {
		return err
	}
	action := "tenant.stop"
	if enabled {
		action = "tenant.start"
	}
	s.audit(ctx, a, action, id, nil)
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	st, err := s.Agent.Status(ctx)
	if err != nil {
		return err
	}
	return s.syncTenant(ctx, t, st, a)
}

// Restart はテナントのコンテナを再起動する（運用の操作）。
func (s *Service) Restart(ctx context.Context, a Actor, id string) error {
	defer s.lock(id)()
	if err := s.Agent.Restart(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "tenant.restart", id, nil)
	return nil
}

// certPEM は証明書を読み直した PEM（前後の余計な文字を落としたもの）。
func certPEM(raw []byte) string { return string(pki.EncodeCert(raw)) }

// ImportClientCA はテナントのクライアントCA の証明書を取り込む。CA が変わったら、前の CA の CRL は捨てる。
func (s *Service) ImportClientCA(ctx context.Context, a Actor, id string, pemData []byte) error {
	defer s.lock(id)()
	ca, err := pki.ParseCert(pemData)
	if err != nil {
		return invalid("クライアントCA の証明書: %v", err)
	}
	if err := pki.CheckClientCA(ca, s.Now()); err != nil {
		return invalid("クライアントCA の証明書: %v", err)
	}
	changed := false
	_, err = s.DB.UpdateTenant(ctx, id, func(t *db.Tenant) error {
		changed = t.ClientCAPEM != certPEM(ca.Raw)
		t.ClientCAPEM = certPEM(ca.Raw)
		return nil
	})
	if err != nil {
		return err
	}
	if changed {
		if err := s.DB.PutCRL(ctx, db.CRL{TenantID: id}); err != nil {
			return err
		}
	}
	s.audit(ctx, a, "client_ca.import", id, map[string]any{"subject": ca.Subject.String(), "serial": pki.SerialHex(ca),
		"not_after": ca.NotAfter.UTC().Format("2006-01-02T15:04:05Z")})
	return nil
}

// CSR は、テナントのサーバー証明書かヘルスチェック用の証明書の鍵を作り直し、CSR（PEM）を返す
// （鍵はエッジの外に出さない。§12.1 の server-csr・probe-csr）。前に出した CSR の鍵は捨てる。
func (s *Service) CSR(ctx context.Context, a Actor, id string, kind keystore.Kind) ([]byte, error) {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return nil, err
	}
	key, err := s.Keys.NewPending(id, kind)
	if err != nil {
		return nil, err
	}
	cn := t.Slug + " server"
	if kind == keystore.Probe {
		cn = names.NASIdentifier(t.Slug, names.ProbeAP)
	}
	csr, err := pki.NewCSR(key, cn)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, a, string(kind)+".csr", id, nil)
	return csr, nil
}

// ImportCert は、署名済みのサーバー証明書かヘルスチェック用の証明書を取り込む。証明書を待っている鍵（CSR を出した鍵）か、
// 今の鍵（同じ鍵での更新）に合うものだけを受け付ける。
func (s *Service) ImportCert(ctx context.Context, a Actor, id string, kind keystore.Kind, pemData []byte) error {
	defer s.lock(id)()
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return err
	}
	c, err := pki.ParseCert(pemData)
	if err != nil {
		return invalid("証明書: %v", err)
	}
	pending, err := s.Keys.Pending(id, kind)
	if err != nil {
		return err
	}
	current, err := s.Keys.Current(id, kind)
	if err != nil {
		return err
	}
	var key []byte
	promote := false
	switch {
	case pending != nil && pki.KeyMatches(c, pending):
		key, promote = pending, true
	case current != nil && pki.KeyMatches(c, current):
		key = current
	default:
		return invalid("証明書が、エッジで作った鍵のものではありません（このテナントの CSR を出し直した場合は、新しい CSR で署名した証明書を取り込んでください）")
	}
	now := s.Now()
	switch kind {
	case keystore.Server:
		if err := pki.CheckServerCert(c, key, t.Slug, s.DNSDomain, now); err != nil {
			return invalid("サーバー証明書: %v", err)
		}
	case keystore.Probe:
		if t.ClientCAPEM == "" {
			return invalid("先にクライアントCA の証明書を取り込んでください")
		}
		ca, err := pki.ParseCert([]byte(t.ClientCAPEM))
		if err != nil {
			return err
		}
		if err := pki.CheckClientCert(c, ca, names.SANURI(s.URNPrefix, t.Slug, names.ProbeAP), now); err != nil {
			return invalid("ヘルスチェック用の証明書: %v", err)
		}
	}
	if promote {
		if err := s.Keys.Promote(id, kind); err != nil {
			return err
		}
	}
	_, err = s.DB.UpdateTenant(ctx, id, func(t *db.Tenant) error {
		if kind == keystore.Server {
			t.ServerCertPEM = certPEM(c.Raw)
		} else {
			t.ProbeCertPEM = certPEM(c.Raw)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.audit(ctx, a, string(kind)+"_cert.import", id, map[string]any{"serial": pki.SerialHex(c),
		"not_after": c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), "new_key": promote})
	return nil
}

// PutAP は AP を登録する。certPEM があれば、テナントのクライアントCA が発行した AP の証明書であることを確かめ、
// シリアル番号と期限を残す（表示用。照合は SAN の URI で行う）。
func (s *Service) PutAP(ctx context.Context, a Actor, id, name string, certPEMData []byte) (db.AP, error) {
	if err := names.CheckAP(name); err != nil {
		return db.AP{}, invalid("AP の名前は、%v", err)
	}
	t, err := s.DB.Tenant(ctx, id)
	if err != nil {
		return db.AP{}, err
	}
	ap := db.AP{TenantID: id, Name: name}
	if strings.TrimSpace(string(certPEMData)) != "" {
		c, err := pki.ParseCert(certPEMData)
		if err != nil {
			return db.AP{}, invalid("AP の証明書: %v", err)
		}
		if t.ClientCAPEM == "" {
			return db.AP{}, invalid("先にクライアントCA の証明書を取り込んでください")
		}
		ca, err := pki.ParseCert([]byte(t.ClientCAPEM))
		if err != nil {
			return db.AP{}, err
		}
		if err := pki.CheckClientCert(c, ca, names.SANURI(s.URNPrefix, t.Slug, name), s.Now()); err != nil {
			return db.AP{}, invalid("AP の証明書: %v", err)
		}
		ap.CertSerial, ap.CertNotAfter = pki.SerialHex(c), c.NotAfter
	}
	ap, err = s.DB.PutAP(ctx, ap)
	if err != nil {
		return db.AP{}, conflict(err, "NAS-Identifier が、ほかの AP と重なっています")
	}
	s.audit(ctx, a, "ap.put", id+"/"+name, map[string]any{"nas_id": ap.NASID, "cert_serial": ap.CertSerial})
	return ap, nil
}

// DeleteAP は AP を消す（次の反映で client ブロックが消える。すぐに効かせるには、CA で証明書を失効させる。§11.1）。
func (s *Service) DeleteAP(ctx context.Context, a Actor, id, name string) error {
	if err := s.DB.DeleteAP(ctx, id, name); err != nil {
		return err
	}
	s.audit(ctx, a, "ap.delete", id+"/"+name, nil)
	return nil
}
