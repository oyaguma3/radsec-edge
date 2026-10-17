package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
)

// AP はテナントの AP。NAS-Identifier・CN・SAN は名前から決まる（names）。
type AP struct {
	TenantID string
	Name     string
	NASID    string
	// CertSerial と CertNotAfter は取り込んだ証明書のシリアル番号（16 進）と期限（表示用。なければ空とゼロ値）。
	CertSerial   string
	CertNotAfter time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// APs はテナントの AP を名前の順に返す。
func (d *DB) APs(ctx context.Context, tenantID string) ([]AP, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT tenant_id, name, nas_id, cert_serial, cert_not_after, created_at, updated_at
		FROM aps WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list aps: %w", err)
	}
	defer rows.Close()
	var out []AP
	for rows.Next() {
		var a AP
		var na, created, updated int64
		if err := rows.Scan(&a.TenantID, &a.Name, &a.NASID, &a.CertSerial, &na, &created, &updated); err != nil {
			return nil, fmt.Errorf("list aps: %w", err)
		}
		a.CertNotAfter, a.CreatedAt, a.UpdatedAt = fromMillis(na), fromMillis(created), fromMillis(updated)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAPs はテナントごとの AP の数を返す。
func (d *DB) CountAPs(ctx context.Context) (map[string]int, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT tenant_id, count(*) FROM aps GROUP BY tenant_id")
	if err != nil {
		return nil, fmt.Errorf("count aps: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// PutAP は AP を登録する（あれば証明書の情報を書き換える）。テナントの望む状態の版を 1 増やす。
// 名前は §8.1 の規則で検証し、NAS-Identifier が他の AP やテナントのヘルスチェックと重なれば ErrConflict。
func (d *DB) PutAP(ctx context.Context, a AP) (AP, error) {
	if err := names.CheckAP(a.Name); err != nil {
		return AP{}, fmt.Errorf("ap name: %w", err)
	}
	now := millis(d.now())
	err := d.tx(ctx, func(tx *sql.Tx) error {
		t, err := tenantQ(ctx, tx, a.TenantID)
		if err != nil {
			return err
		}
		a.NASID = names.NASIdentifier(t.Slug, a.Name)
		var exists int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM aps WHERE tenant_id = ? AND name = ?", a.TenantID, a.Name).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if err := checkNASFree(ctx, tx, a.NASID); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO aps (tenant_id, name, nas_id, cert_serial, cert_not_after, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, a.TenantID, a.Name, a.NASID, a.CertSerial, millis(a.CertNotAfter), now, now)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE aps SET cert_serial = ?, cert_not_after = ?, updated_at = ? WHERE tenant_id = ? AND name = ?`,
				a.CertSerial, millis(a.CertNotAfter), now, a.TenantID, a.Name)
		}
		if isUnique(err) {
			return fmt.Errorf("%w: the NAS-Identifier %s is already used", ErrConflict, a.NASID)
		}
		if err != nil {
			return err
		}
		return touchTenant(ctx, tx, a.TenantID, now)
	})
	if err != nil {
		return AP{}, fmt.Errorf("put ap %s/%s: %w", a.TenantID, a.Name, err)
	}
	a.UpdatedAt = fromMillis(now)
	return a, nil
}

// DeleteAP は AP を消し、テナントの望む状態の版を 1 増やす。なければ ErrNotFound。
func (d *DB) DeleteAP(ctx context.Context, tenantID, name string) error {
	err := d.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM aps WHERE tenant_id = ? AND name = ?", tenantID, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return touchTenant(ctx, tx, tenantID, millis(d.now()))
	})
	if err != nil {
		return fmt.Errorf("delete ap %s/%s: %w", tenantID, name, err)
	}
	return nil
}
