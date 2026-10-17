package db

import (
	"context"
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
)

// Apply は反映の 1 回の記録。
type Apply struct {
	ID       int64
	TenantID string
	Version  int64
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

// InsertApply は反映の記録を書き込む。
func (d *DB) InsertApply(ctx context.Context, a Apply) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO applies (tenant_id, version, hash, trigger, action, result, error, operator, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, a.TenantID, a.Version, a.Hash, a.Trigger, a.Action, a.Result, a.Error, a.Operator,
		millis(a.Started), millis(a.Finished))
	if err != nil {
		return fmt.Errorf("insert apply: %w", err)
	}
	return nil
}

// Applies はテナントの反映の記録を新しい順に limit 件返す。
func (d *DB) Applies(ctx context.Context, tenantID string, limit int) ([]Apply, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, tenant_id, version, hash, trigger, action, result, error, operator, started_at, finished_at
		FROM applies WHERE tenant_id = ? ORDER BY id DESC LIMIT ?`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list applies: %w", err)
	}
	defer rows.Close()
	var out []Apply
	for rows.Next() {
		var a Apply
		var s, f int64
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Version, &a.Hash, &a.Trigger, &a.Action, &a.Result, &a.Error, &a.Operator, &s, &f); err != nil {
			return nil, fmt.Errorf("list applies: %w", err)
		}
		a.Started, a.Finished = fromMillis(s), fromMillis(f)
		out = append(out, a)
	}
	return out, rows.Err()
}
