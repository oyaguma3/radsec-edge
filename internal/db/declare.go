package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/netip"

	"github.com/oyaguma3/radsec-edge/internal/names"
)

// Declaration は中央（OSS/BSS）が送るテナントの望む状態の全部（§24.11 の EA2）。値は呼び出し側で検証する。
type Declaration struct {
	ID, Slug string
	// Revision は中央が付けた版。エッジは覚えるだけで、新旧を判断しない（EA3）。
	Revision                   int64
	Port                       int
	AuthUpstream, AcctUpstream netip.AddrPort
	// ClientCAPEM は発行した CA の証明書。Brought は持ち込みの CA の一覧。
	ClientCAPEM             string
	Brought                 []BroughtCA
	SourceCIDRs             []netip.Prefix
	MatchAttr, MatchPattern string
	// APs は AP とグループの一覧（名前の順でなくてよい）。
	APs []AP
	// Capacity は 1 台のテナントの数の上限（0 なら確かめない）。新しいテナントのときだけ確かめる。
	Capacity int
}

// DeclareResult は Declare の結果。
type DeclareResult struct {
	Tenant Tenant
	// Created は新しいテナントを作ったか。Changed は設定が変わったか（内部の版を上げたか）。
	Created, Changed bool
}

// Declare はテナントの望む状態をまるごと置き換える（1 つのトランザクション）。設定が変わったときだけ内部の版を上げる
// （版だけ・表示だけの違いでは未反映にしない。EA3）。発行した CA の証明書が変わったら、その CRL は消す。
func (d *DB) Declare(ctx context.Context, dc Declaration) (DeclareResult, error) {
	spec := TenantSpec{ID: dc.ID, Slug: dc.Slug, Port: dc.Port, AuthUpstream: dc.AuthUpstream, AcctUpstream: dc.AcctUpstream}
	if err := spec.check(); err != nil {
		return DeclareResult{}, err
	}
	var res DeclareResult
	err := d.tx(ctx, func(tx *sql.Tx) error {
		now := millis(d.now())
		cur, err := tenantQ(ctx, tx, dc.ID)
		switch {
		case errors.Is(err, ErrNotFound):
			res.Created, res.Changed = true, true
			if err := createForDeclare(ctx, tx, dc, now); err != nil {
				return err
			}
			if cur, err = tenantQ(ctx, tx, dc.ID); err != nil {
				return err
			}
		case err != nil:
			return err
		case cur.Slug != dc.Slug:
			return fmt.Errorf("%w (%s to %s)", ErrSlugImmutable, cur.Slug, dc.Slug)
		}
		caChanged := cur.ClientCAPEM != dc.ClientCAPEM
		brought, err := broughtDiffers(ctx, tx, dc)
		if err != nil {
			return err
		}
		apsChanged, err := replaceAPs(ctx, tx, dc, now)
		if err != nil {
			return err
		}
		if caChanged || brought || apsChanged || cur.Port != dc.Port || cur.AuthUpstream != dc.AuthUpstream || cur.AcctUpstream != dc.AcctUpstream ||
			joinCIDRs(cur.SourceCIDRs) != joinCIDRs(dc.SourceCIDRs) || cur.SharedMatchAttr != dc.MatchAttr || cur.SharedMatchPattern != dc.MatchPattern {
			res.Changed = true
		}
		if err := replaceBrought(ctx, tx, dc.ID, dc.Brought, now); err != nil {
			return err
		}
		if caChanged {
			if _, err := tx.ExecContext(ctx, "DELETE FROM crls WHERE tenant_id = ? AND ca_id = ''", dc.ID); err != nil {
				return err
			}
		}
		bump := 0
		if res.Changed && !res.Created {
			bump = 1
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenants SET port = ?, auth_upstream = ?, acct_upstream = ?, client_ca_pem = ?, source_cidrs = ?,
			shared_match_attr = ?, shared_match_pattern = ?, revision = ?, desired_version = desired_version + ?, updated_at = ? WHERE id = ?`,
			dc.Port, dc.AuthUpstream.String(), dc.AcctUpstream.String(), dc.ClientCAPEM, joinCIDRs(dc.SourceCIDRs), dc.MatchAttr, dc.MatchPattern,
			dc.Revision, bump, now, dc.ID)
		if isUnique(err) {
			return fmt.Errorf("%w: the port %d is already used", ErrConflict, dc.Port)
		}
		if err != nil {
			return err
		}
		res.Tenant, err = tenantQ(ctx, tx, dc.ID)
		return err
	})
	if err != nil {
		return DeclareResult{}, fmt.Errorf("declare tenant %s: %w", dc.ID, err)
	}
	return res, nil
}

// createForDeclare は新しいテナントの行を作る（上限とポート・slug の重なりを確かめる）。
func createForDeclare(ctx context.Context, tx *sql.Tx, dc Declaration, now int64) error {
	if dc.Capacity > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM tenants").Scan(&n); err != nil {
			return err
		}
		if n >= dc.Capacity {
			return fmt.Errorf("%w (%d)", ErrCapacity, dc.Capacity)
		}
	}
	if err := checkNASFree(ctx, tx, names.NASIdentifier(dc.Slug, names.ProbeAP)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, slug, port, auth_upstream, acct_upstream, crl_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, '', ?, ?)`, dc.ID, dc.Slug, dc.Port, dc.AuthUpstream.String(), dc.AcctUpstream.String(), now, now)
	if isUnique(err) {
		return fmt.Errorf("%w: the slug or port is already used", ErrConflict)
	}
	return err
}

// broughtDiffers は持ち込みの CA の一覧が今のものと違うか。
func broughtDiffers(ctx context.Context, tx *sql.Tx, dc Declaration) (bool, error) {
	type ca struct {
		cert string
		crl  bool
	}
	cur := map[string]ca{}
	rows, err := tx.QueryContext(ctx, "SELECT ca_id, cert_pem, has_crl FROM tenant_brought_cas WHERE tenant_id = ?", dc.ID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var c ca
		if err := rows.Scan(&id, &c.cert, &c.crl); err != nil {
			return false, err
		}
		cur[id] = c
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	want := map[string]ca{}
	for _, b := range dc.Brought {
		want[b.CAID] = ca{b.CertPEM, b.HasCRL}
	}
	return !maps.Equal(cur, want), nil
}

// replaceAPs は AP とグループの一覧を置き換え、設定に効く違い（名前と種類）があったかを返す。用途と証明書の情報は表示だけなので、
// 書き換えても設定は変わらない。
func replaceAPs(ctx context.Context, tx *sql.Tx, dc Declaration, now int64) (bool, error) {
	type row struct {
		kind, purpose, serial string
		notAfter              int64
	}
	cur := map[string]row{}
	rows, err := tx.QueryContext(ctx, "SELECT name, kind, purpose, cert_serial, cert_not_after FROM aps WHERE tenant_id = ?", dc.ID)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var name string
		var r row
		if err := rows.Scan(&name, &r.kind, &r.purpose, &r.serial, &r.notAfter); err != nil {
			rows.Close()
			return false, err
		}
		cur[name] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	changed := false
	want := map[string]bool{}
	for _, a := range dc.APs {
		want[a.Name] = true
	}
	// 先に消す（別のテナントへ移したのではなく、このテナントの中の名前の入れ替えで NAS-Identifier がぶつからないように）。
	for name := range cur {
		if want[name] {
			continue
		}
		changed = true
		if _, err := tx.ExecContext(ctx, "DELETE FROM aps WHERE tenant_id = ? AND name = ?", dc.ID, name); err != nil {
			return false, err
		}
	}
	for _, a := range dc.APs {
		r, ok := cur[a.Name]
		switch {
		case !ok:
			changed = true
			nas := names.NASIdentifier(dc.Slug, a.Name)
			if err := checkNASFree(ctx, tx, nas); err != nil {
				return false, err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO aps (tenant_id, name, nas_id, kind, purpose, cert_serial, cert_not_after, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, dc.ID, a.Name, nas, a.Kind, a.Purpose, a.CertSerial, millis(a.CertNotAfter), now, now)
			if isUnique(err) {
				return false, fmt.Errorf("%w: the NAS-Identifier %s is already used", ErrConflict, nas)
			}
		case r.kind != a.Kind:
			changed = true
			_, err = tx.ExecContext(ctx, "UPDATE aps SET kind = ?, purpose = ?, cert_serial = ?, cert_not_after = ?, updated_at = ? WHERE tenant_id = ? AND name = ?",
				a.Kind, a.Purpose, a.CertSerial, millis(a.CertNotAfter), now, dc.ID, a.Name)
		case r.purpose != a.Purpose || r.serial != a.CertSerial || r.notAfter != millis(a.CertNotAfter):
			_, err = tx.ExecContext(ctx, "UPDATE aps SET purpose = ?, cert_serial = ?, cert_not_after = ?, updated_at = ? WHERE tenant_id = ? AND name = ?",
				a.Purpose, a.CertSerial, millis(a.CertNotAfter), now, dc.ID, a.Name)
		}
		if err != nil {
			return false, err
		}
	}
	return changed, nil
}
