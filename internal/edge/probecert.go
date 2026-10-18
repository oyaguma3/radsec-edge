package edge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// ErrProbeRevoked は、ヘルスチェック用の証明書が CRL で失効していることを表す（設計概要 §11.3）。
var ErrProbeRevoked = errors.New("ヘルスチェック用の証明書が失効しています。CSR を出し直して、署名した証明書を取り込んでください")

// checkProbeCert は、ヘルスチェック用の証明書が今のクライアントCA で検証でき、期限の中にあり、crlPEM の CRL で失効して
// いないことを確かめる（設計概要 §11.2、§11.3）。失効していれば ErrProbeRevoked を返す。crlPEM が空なら失効は見ない。
func (s *Service) checkProbeCert(t db.Tenant, crlPEM []byte) error {
	if t.ClientCAPEM == "" || t.ProbeCertPEM == "" {
		return nil // 足りないものは Missing で出す
	}
	ca, err := pki.ParseCert([]byte(t.ClientCAPEM))
	if err != nil {
		return err
	}
	probe, err := pki.ParseCert([]byte(t.ProbeCertPEM))
	if err != nil {
		return err
	}
	if err := pki.CheckClientCert(probe, ca, names.SANURI(s.URNPrefix, t.Slug, names.ProbeAP), s.Now()); err != nil {
		return fmt.Errorf("ヘルスチェック用の証明書が、今のクライアントCA で検証できません（%v）。CSR を出し直して、このクライアントCA で署名した証明書を取り込んでください", err)
	}
	if len(strings.TrimSpace(string(crlPEM))) == 0 {
		return nil
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		return err
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(probe.SerialNumber) == 0 {
			return ErrProbeRevoked
		}
	}
	return nil
}

// ProbeProblem は、ヘルスチェック用の証明書の問題（失効、今のクライアントCA で検証できない、期限切れ）を画面に出す文で返す。
// 問題がなければ空。
func (s *Service) ProbeProblem(ctx context.Context, t db.Tenant) (string, error) {
	crl, err := s.DB.CRL(ctx, t.ID)
	if err != nil {
		return "", err
	}
	if err := s.checkProbeCert(t, []byte(crl.PEM)); err != nil {
		return err.Error(), nil
	}
	return "", nil
}

// healthCheck は反映の後のヘルスチェックを行う。ヘルスチェック用の証明書が crlPEM の CRL で失効しているときは、Status-Server を
// 送れないので、コンテナが動いていることだけを確かめる（CRL の失効を優先する。設計概要 §11.3）。
func (s *Service) healthCheck(ctx context.Context, t db.Tenant, port int, crlPEM []byte) error {
	if !errors.Is(s.checkProbeCert(t, crlPEM), ErrProbeRevoked) {
		return s.probeUntil(ctx, t, port)
	}
	s.Log.Warn("the probe certificate is revoked; checking only that the container is running", "tenant", t.ID)
	ctx, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
	defer cancel()
	for {
		st, err := s.Agent.Status(ctx)
		if err == nil {
			if c, ok := st.Container(t.ID); ok && c.Running && !c.Restarting {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("コンテナが動いていません（ヘルスチェック用の証明書が失効しているので、Status-Server は送っていません）")
		case <-time.After(300 * time.Millisecond):
		}
	}
}
