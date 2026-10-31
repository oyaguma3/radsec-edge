package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// CRL はテナントと CA の組の CRL の状態（設計概要 §9.5、§24.6）。
type CRL struct {
	TenantID string
	// CAID は持ち込みの CA の ID。発行した CA の CRL なら空。
	CAID string
	// PEM は最後に置いた（検証を通った）CRL。まだなければ空。
	PEM string
	// Number は CRL の番号（10 進。番号のない CRL なら空）。
	Number                 string
	ThisUpdate, NextUpdate time.Time
	// Source は fetch（CA から取得）か upload（画面から取り込み）。
	Source      string
	InstalledAt time.Time
	// ETag は最後に取得したときの ETag（If-None-Match に使う）。
	ETag string
	// LastAttemptAt と LastSuccessAt は最後に取得を試みた・成功した時刻、LastError は最後の失敗の理由（成功したら空）。
	LastAttemptAt, LastSuccessAt time.Time
	LastError                    string
}

// CRL は発行した CA の CRL の状態を返す。まだなければ、TenantID だけの値を返す。
func (d *DB) CRL(ctx context.Context, tenantID string) (CRL, error) {
	return d.CRLOf(ctx, tenantID, "")
}

// CRLOf はテナントと CA の組の CRL の状態を返す（caID が空なら発行した CA）。まだなければ、キーだけの値を返す。
func (d *DB) CRLOf(ctx context.Context, tenantID, caID string) (CRL, error) {
	c := CRL{TenantID: tenantID, CAID: caID}
	var this, next, inst, att, succ int64
	err := d.sql.QueryRowContext(ctx, `SELECT pem, number, this_update, next_update, source, installed_at, etag,
		last_attempt_at, last_success_at, last_error FROM crls WHERE tenant_id = ? AND ca_id = ?`, tenantID, caID).
		Scan(&c.PEM, &c.Number, &this, &next, &c.Source, &inst, &c.ETag, &att, &succ, &c.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return CRL{}, fmt.Errorf("get crl %s %s: %w", tenantID, caID, err)
	}
	c.ThisUpdate, c.NextUpdate, c.InstalledAt = fromMillis(this), fromMillis(next), fromMillis(inst)
	c.LastAttemptAt, c.LastSuccessAt = fromMillis(att), fromMillis(succ)
	return c, nil
}

// PutCRL はテナントと CA の組の CRL の状態を書き込む。
func (d *DB) PutCRL(ctx context.Context, c CRL) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO crls (tenant_id, ca_id, pem, number, this_update, next_update, source, installed_at, etag,
			last_attempt_at, last_success_at, last_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, ca_id) DO UPDATE SET pem = excluded.pem, number = excluded.number, this_update = excluded.this_update,
			next_update = excluded.next_update, source = excluded.source, installed_at = excluded.installed_at, etag = excluded.etag,
			last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at, last_error = excluded.last_error`,
		c.TenantID, c.CAID, c.PEM, c.Number, millis(c.ThisUpdate), millis(c.NextUpdate), c.Source, millis(c.InstalledAt), c.ETag,
		millis(c.LastAttemptAt), millis(c.LastSuccessAt), c.LastError)
	if err != nil {
		return fmt.Errorf("put crl %s %s: %w", c.TenantID, c.CAID, err)
	}
	return nil
}

// BroughtCA はテナントの持ち込みの CA（§24.3）。
type BroughtCA struct {
	TenantID string
	// CAID は radsec-ca の ID（brought.<slug>.<名前>）。
	CAID string
	// CertPEM は CA の証明書。HasCRL は CRL があるか（ないと、そのテナントは CRLCheck off になる）。
	CertPEM   string
	HasCRL    bool
	CreatedAt time.Time
}

// BroughtCAs はテナントの持ち込みの CA を ID の順に返す。
func (d *DB) BroughtCAs(ctx context.Context, tenantID string) ([]BroughtCA, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT ca_id, cert_pem, has_crl, created_at FROM tenant_brought_cas WHERE tenant_id = ? ORDER BY ca_id", tenantID)
	if err != nil {
		return nil, fmt.Errorf("list brought cas: %w", err)
	}
	defer rows.Close()
	var out []BroughtCA
	for rows.Next() {
		b := BroughtCA{TenantID: tenantID}
		var created int64
		if err := rows.Scan(&b.CAID, &b.CertPEM, &b.HasCRL, &created); err != nil {
			return nil, fmt.Errorf("list brought cas: %w", err)
		}
		b.CreatedAt = fromMillis(created)
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetTrust は、テナントの持ち込みの CA の一覧をまるごと置き換え、送信元の範囲と共通のブロックの照合の形を書き、望む状態の版を 1 増やす
// （1 つのトランザクション。§24.6）。一覧から外した CA と、CA の証明書を替えた CA の CRL は消す。
func (d *DB) SetTrust(ctx context.Context, id string, cas []BroughtCA, cidrs []netip.Prefix, matchAttr, matchPattern string) error {
	err := d.tx(ctx, func(tx *sql.Tx) error {
		now := millis(d.now())
		res, err := tx.ExecContext(ctx, "UPDATE tenants SET source_cidrs = ?, shared_match_attr = ?, shared_match_pattern = ?, desired_version = desired_version + 1, updated_at = ? WHERE id = ?",
			joinCIDRs(cidrs), matchAttr, matchPattern, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		old := map[string]string{}
		rows, err := tx.QueryContext(ctx, "SELECT ca_id, cert_pem FROM tenant_brought_cas WHERE tenant_id = ?", id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var caID, cert string
			if err := rows.Scan(&caID, &cert); err != nil {
				rows.Close()
				return err
			}
			old[caID] = cert
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, c := range cas {
			prev, existed := old[c.CAID]
			delete(old, c.CAID)
			if existed && prev != c.CertPEM {
				if _, err := tx.ExecContext(ctx, "DELETE FROM crls WHERE tenant_id = ? AND ca_id = ?", id, c.CAID); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_brought_cas (tenant_id, ca_id, cert_pem, has_crl, created_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (tenant_id, ca_id) DO UPDATE SET cert_pem = excluded.cert_pem, has_crl = excluded.has_crl`, id, c.CAID, c.CertPEM, c.HasCRL, now); err != nil {
				return err
			}
		}
		for caID := range old {
			if _, err := tx.ExecContext(ctx, "DELETE FROM tenant_brought_cas WHERE tenant_id = ? AND ca_id = ?", id, caID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM crls WHERE tenant_id = ? AND ca_id = ?", id, caID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("set trust of %s: %w", id, err)
	}
	return nil
}
