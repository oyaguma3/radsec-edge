package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
)

// Tenant はテナントの望む状態と反映の状態。
type Tenant struct {
	// ID は管理モードでは OSS/BSS の値、単独モードでは Slug と同じ。
	ID   string
	Slug string
	Port int
	// AuthUpstream と AcctUpstream は上流の認証と課金（IP アドレスとポート）。
	AuthUpstream, AcctUpstream netip.AddrPort
	// CRLURL は CRL の取得先（空なら EDGE_CRL_BASE_URL から決める）。
	CRLURL string
	// ClientCAPEM はテナントのクライアントCA の証明書、ServerCertPEM はテナントのサーバー証明書、
	// ProbeCertPEM はヘルスチェック用の証明書（どれも PEM。まだなければ空）。
	ClientCAPEM, ServerCertPEM, ProbeCertPEM string
	Enabled                                  bool
	// DesiredVersion は望む状態の版、AppliedVersion と AppliedHash は反映済みの版と設定のハッシュ。
	DesiredVersion, AppliedVersion  int64
	AppliedHash                     string
	AppliedAt, CreatedAt, UpdatedAt time.Time
}

// Pending は未反映の変更があるか。
func (t Tenant) Pending() bool { return t.AppliedVersion < t.DesiredVersion }

const tenantColumns = `id, slug, port, auth_upstream, acct_upstream, crl_url, client_ca_pem, server_cert_pem, probe_cert_pem,
	enabled, desired_version, applied_version, applied_hash, applied_at, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanTenant(s scanner) (Tenant, error) {
	var t Tenant
	var auth, acct string
	var applied, created, updated int64
	err := s.Scan(&t.ID, &t.Slug, &t.Port, &auth, &acct, &t.CRLURL, &t.ClientCAPEM, &t.ServerCertPEM, &t.ProbeCertPEM,
		&t.Enabled, &t.DesiredVersion, &t.AppliedVersion, &t.AppliedHash, &applied, &created, &updated)
	if err != nil {
		return Tenant{}, err
	}
	if t.AuthUpstream, err = netip.ParseAddrPort(auth); err != nil {
		return Tenant{}, fmt.Errorf("tenant %s: auth_upstream: %w", t.ID, err)
	}
	if t.AcctUpstream, err = netip.ParseAddrPort(acct); err != nil {
		return Tenant{}, fmt.Errorf("tenant %s: acct_upstream: %w", t.ID, err)
	}
	t.AppliedAt, t.CreatedAt, t.UpdatedAt = fromMillis(applied), fromMillis(created), fromMillis(updated)
	return t, nil
}

// Tenants はすべてのテナントを slug の順に返す。
func (d *DB) Tenants(ctx context.Context) ([]Tenant, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT "+tenantColumns+" FROM tenants ORDER BY slug")
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, fmt.Errorf("list tenants: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Tenant は ID のテナントを返す。なければ ErrNotFound。
func (d *DB) Tenant(ctx context.Context, id string) (Tenant, error) {
	return tenantQ(ctx, d.sql, id)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func tenantQ(ctx context.Context, q querier, id string) (Tenant, error) {
	t, err := scanTenant(q.QueryRowContext(ctx, "SELECT "+tenantColumns+" FROM tenants WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant %s: %w", id, err)
	}
	return t, nil
}

// TenantSpec はテナントを作る・変えるときに与える値。
type TenantSpec struct {
	ID, Slug                   string
	Port                       int
	AuthUpstream, AcctUpstream netip.AddrPort
	CRLURL                     string
}

func (s TenantSpec) check() error {
	if err := names.CheckTenant(s.Slug); err != nil {
		return fmt.Errorf("slug: %w", err)
	}
	if !names.ValidSlug(s.ID) {
		return fmt.Errorf("id: %w", names.ErrSlug)
	}
	if s.Port < 20830 || s.Port > 20999 {
		return errors.New("port: must be between 20830 and 20999")
	}
	if !s.AuthUpstream.IsValid() || !s.AcctUpstream.IsValid() {
		return errors.New("upstream: must be an IP address and port")
	}
	return nil
}

// CreateTenant はテナントを作る（有効、版 1、反映は未）。slug・ID・ポートが重なれば ErrConflict。
// テナントのヘルスチェック用の NAS-Identifier（<slug>-probe）が既存の AP と重なっても ErrConflict（§8.2）。
func (d *DB) CreateTenant(ctx context.Context, s TenantSpec) (Tenant, error) {
	if err := s.check(); err != nil {
		return Tenant{}, err
	}
	now := millis(d.now())
	var t Tenant
	err := d.tx(ctx, func(tx *sql.Tx) error {
		if err := checkNASFree(ctx, tx, names.NASIdentifier(s.Slug, names.ProbeAP)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, slug, port, auth_upstream, acct_upstream, crl_url, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, s.ID, s.Slug, s.Port, s.AuthUpstream.String(), s.AcctUpstream.String(), s.CRLURL, now, now)
		if isUnique(err) {
			return fmt.Errorf("%w: the tenant ID, slug or port is already used", ErrConflict)
		}
		if err != nil {
			return err
		}
		t, err = tenantQ(ctx, tx, s.ID)
		return err
	})
	if err != nil {
		return Tenant{}, fmt.Errorf("create tenant: %w", err)
	}
	return t, nil
}

// UpdateTenant は、テナントを読んで fn で変え、望む状態の版を 1 増やして書き戻す。fn が変えてよいのは
// ポート、上流、CRL の取得先、証明書、有効・無効だけ（ID と slug は変えない）。fn がエラーを返したら何もしない。
func (d *DB) UpdateTenant(ctx context.Context, id string, fn func(*Tenant) error) (Tenant, error) {
	var out Tenant
	err := d.tx(ctx, func(tx *sql.Tx) error {
		t, err := tenantQ(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := fn(&t); err != nil {
			return err
		}
		spec := TenantSpec{ID: id, Slug: t.Slug, Port: t.Port, AuthUpstream: t.AuthUpstream, AcctUpstream: t.AcctUpstream, CRLURL: t.CRLURL}
		if err := spec.check(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenants SET port = ?, auth_upstream = ?, acct_upstream = ?, crl_url = ?,
			client_ca_pem = ?, server_cert_pem = ?, probe_cert_pem = ?, enabled = ?,
			desired_version = desired_version + 1, updated_at = ? WHERE id = ?`,
			t.Port, t.AuthUpstream.String(), t.AcctUpstream.String(), t.CRLURL, t.ClientCAPEM, t.ServerCertPEM, t.ProbeCertPEM,
			t.Enabled, millis(d.now()), id)
		if isUnique(err) {
			return fmt.Errorf("%w: the port is already used", ErrConflict)
		}
		if err != nil {
			return err
		}
		out, err = tenantQ(ctx, tx, id)
		return err
	})
	if err != nil {
		return Tenant{}, fmt.Errorf("update tenant %s: %w", id, err)
	}
	return out, nil
}

// touchTenant は望む状態の版だけを 1 増やす（AP の追加・削除など、テナントの行の外の変更）。
func touchTenant(ctx context.Context, tx *sql.Tx, id string, now int64) error {
	res, err := tx.ExecContext(ctx, "UPDATE tenants SET desired_version = desired_version + 1, updated_at = ? WHERE id = ?", now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkApplied は版 version を反映済みにする（ハッシュと時刻も残す）。反映の間に望む状態が進んでいても、
// 反映した版の番号を残すので、次の反映でその先を反映する。
func (d *DB) MarkApplied(ctx context.Context, id string, version int64, hash string) error {
	_, err := d.sql.ExecContext(ctx, "UPDATE tenants SET applied_version = ?, applied_hash = ?, applied_at = ? WHERE id = ?",
		version, hash, millis(d.now()), id)
	if err != nil {
		return fmt.Errorf("mark applied %s: %w", id, err)
	}
	return nil
}

// DeleteTenant はテナントを消す（AP と CRL も消える。反映の履歴と監査ログは残す）。
func (d *DB) DeleteTenant(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, "DELETE FROM tenants WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete tenant %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// FreePort は使われていないポートのうち最も小さいものを返す。空きがなければ ErrConflict。
func (d *DB) FreePort(ctx context.Context, min, max int) (int, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT port FROM tenants ORDER BY port")
	if err != nil {
		return 0, fmt.Errorf("free port: %w", err)
	}
	defer rows.Close()
	used := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return 0, err
		}
		used[p] = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for p := min; p <= max; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("%w: no free port between %d and %d", ErrConflict, min, max)
}

// checkNASFree は、NAS-Identifier が AP にもテナントのヘルスチェックにも使われていないことを確かめる。
func checkNASFree(ctx context.Context, tx *sql.Tx, nasID string) error {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM aps WHERE nas_id = ?) +
		(SELECT count(*) FROM tenants WHERE slug || '-probe' = ?)`, nasID, nasID).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: the NAS-Identifier %s is already used", ErrConflict, nasID)
	}
	return nil
}
