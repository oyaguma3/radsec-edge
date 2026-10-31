package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// 反映のきっかけ（Apply.Trigger）。
const (
	TriggerApply     = "apply"     // 運用者の「反映」
	TriggerReconcile = "reconcile" // 整合ループ（コンテナがない・止まっているなど）
	TriggerCRL       = "crl"       // CRL の更新
)

// 反映の結果（Apply.Result）。
const (
	ResultOK         = "ok"
	ResultFailed     = "failed"      // 反映できず、前の版のまま
	ResultRolledBack = "rolled_back" // 反映した後のヘルスチェックに失敗し、前の版に戻した
	// ResultInterrupted は、反映の途中でプロセスが止まっていたので、前の版に戻した（§24.11 の EA6）。
	ResultInterrupted = "interrupted"
)

// Apply は反映の 1 回の記録。
type Apply struct {
	ID       int64
	TenantID string
	Version  int64
	// Revision は中央（OSS/BSS）が付けた望む状態の版（単独モードでは 0）。
	Revision int64
	Hash     string
	Trigger  string
	// Action は行った操作（none / start / sighup / restart / stop / remove）。
	Action   string
	Result   string
	Error    string
	Operator string
	Started  time.Time
	Finished time.Time
}

const applyColumns = "id, tenant_id, version, revision, hash, trigger, action, result, error, operator, started_at, finished_at"

func scanApply(s scanner) (Apply, error) {
	var a Apply
	var started, finished int64
	if err := s.Scan(&a.ID, &a.TenantID, &a.Version, &a.Revision, &a.Hash, &a.Trigger, &a.Action, &a.Result, &a.Error, &a.Operator, &started, &finished); err != nil {
		return Apply{}, err
	}
	a.Started, a.Finished = fromMillis(started), fromMillis(finished)
	return a, nil
}

// InsertApply は反映の記録を書き込む。
func (d *DB) InsertApply(ctx context.Context, a Apply) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO applies (tenant_id, version, revision, hash, trigger, action, result, error, operator, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, a.TenantID, a.Version, a.Revision, a.Hash, a.Trigger, a.Action, a.Result, a.Error, a.Operator,
		millis(a.Started), millis(a.Finished))
	if err != nil {
		return fmt.Errorf("insert apply: %w", err)
	}
	return nil
}

// Applies はテナントの反映の記録を新しい順に limit 件返す。
func (d *DB) Applies(ctx context.Context, tenantID string, limit int) ([]Apply, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT "+applyColumns+" FROM applies WHERE tenant_id = ? ORDER BY id DESC LIMIT ?", tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list applies: %w", err)
	}
	defer rows.Close()
	var out []Apply
	for rows.Next() {
		a, err := scanApply(rows)
		if err != nil {
			return nil, fmt.Errorf("list applies: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// LastApply はテナントの最後の反映（整合ループと CRL の更新を除く）の記録を返す。なければ ErrNotFound。
func (d *DB) LastApply(ctx context.Context, tenantID string) (Apply, error) {
	a, err := scanApply(d.sql.QueryRowContext(ctx, "SELECT "+applyColumns+" FROM applies WHERE tenant_id = ? AND trigger = ? ORDER BY id DESC LIMIT 1", tenantID, TriggerApply))
	if errors.Is(err, sql.ErrNoRows) {
		return Apply{}, ErrNotFound
	}
	if err != nil {
		return Apply{}, fmt.Errorf("last apply %s: %w", tenantID, err)
	}
	return a, nil
}
