package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CRL はテナントの CRL の状態（設計概要 §9.5）。
type CRL struct {
	TenantID string
	// PEM は最後に置いた（検証を通った）CRL。まだなければ空。
	PEM string
	// Number は CRL の番号（10 進）。
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

// CRL はテナントの CRL の状態を返す。まだなければ、TenantID だけの値を返す。
func (d *DB) CRL(ctx context.Context, tenantID string) (CRL, error) {
	c := CRL{TenantID: tenantID}
	var this, next, inst, att, succ int64
	err := d.sql.QueryRowContext(ctx, `SELECT pem, number, this_update, next_update, source, installed_at, etag,
		last_attempt_at, last_success_at, last_error FROM crls WHERE tenant_id = ?`, tenantID).
		Scan(&c.PEM, &c.Number, &this, &next, &c.Source, &inst, &c.ETag, &att, &succ, &c.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return CRL{}, fmt.Errorf("get crl %s: %w", tenantID, err)
	}
	c.ThisUpdate, c.NextUpdate, c.InstalledAt = fromMillis(this), fromMillis(next), fromMillis(inst)
	c.LastAttemptAt, c.LastSuccessAt = fromMillis(att), fromMillis(succ)
	return c, nil
}

// PutCRL はテナントの CRL の状態を書き込む。
func (d *DB) PutCRL(ctx context.Context, c CRL) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO crls (tenant_id, pem, number, this_update, next_update, source, installed_at, etag,
			last_attempt_at, last_success_at, last_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET pem = excluded.pem, number = excluded.number, this_update = excluded.this_update,
			next_update = excluded.next_update, source = excluded.source, installed_at = excluded.installed_at, etag = excluded.etag,
			last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at, last_error = excluded.last_error`,
		c.TenantID, c.PEM, c.Number, millis(c.ThisUpdate), millis(c.NextUpdate), c.Source, millis(c.InstalledAt), c.ETag,
		millis(c.LastAttemptAt), millis(c.LastSuccessAt), c.LastError)
	if err != nil {
		return fmt.Errorf("put crl %s: %w", c.TenantID, err)
	}
	return nil
}
