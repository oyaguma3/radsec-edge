package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IdempotencyState は、Idempotency-Key の要求を始めたときの状態（設計概要 §12.1）。
type IdempotencyState int

const (
	// IdempotencyNew は初めての要求（処理してよい）。
	IdempotencyNew IdempotencyState = iota
	// IdempotencyInProgress は、同じキーの最初の要求がまだ処理中。
	IdempotencyInProgress
	// IdempotencyMismatch は、同じキーで内容の違う要求が以前に届いている。
	IdempotencyMismatch
	// IdempotencyReplay は、同じ要求の応答を覚えている（それを返す）。
	IdempotencyReplay
)

// StoredResponse は覚えておく応答。
type StoredResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// BeginIdempotent は Idempotency-Key の要求を始める。初めてなら処理中として pendingTTL のあいだ記録する
// （プロセスが落ちても、その時間が過ぎればやり直せる）。期限の切れた記録はないものとして扱う。
func (d *DB) BeginIdempotent(ctx context.Context, mgmtClient, key, reqHash string, pendingTTL time.Duration) (IdempotencyState, StoredResponse, error) {
	var state IdempotencyState
	var stored StoredResponse
	now := d.now()
	err := d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM idempotency WHERE mgmt_client = ? AND key = ? AND expires_at <= ?", mgmtClient, key, millis(now)); err != nil {
			return err
		}
		var hash, status string
		err := tx.QueryRowContext(ctx, "SELECT req_hash, status, resp_status, resp_type, response FROM idempotency WHERE mgmt_client = ? AND key = ?",
			mgmtClient, key).Scan(&hash, &status, &stored.Status, &stored.ContentType, &stored.Body)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			state = IdempotencyNew
			_, err = tx.ExecContext(ctx, `INSERT INTO idempotency (mgmt_client, key, req_hash, status, created_at, expires_at) VALUES (?, ?, ?, 'pending', ?, ?)`,
				mgmtClient, key, reqHash, millis(now), millis(now.Add(pendingTTL)))
			return err
		case err != nil:
			return err
		case hash != reqHash:
			state = IdempotencyMismatch
		case status != "done":
			state = IdempotencyInProgress
		default:
			state = IdempotencyReplay
		}
		return nil
	})
	if err != nil {
		return 0, StoredResponse{}, fmt.Errorf("begin idempotent: %w", err)
	}
	return state, stored, nil
}

// CompleteIdempotent は、処理中の記録に応答を書き、ttl のあいだ覚える。
func (d *DB) CompleteIdempotent(ctx context.Context, mgmtClient, key, reqHash string, resp StoredResponse, ttl time.Duration) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE idempotency SET status = 'done', resp_status = ?, resp_type = ?, response = ?, expires_at = ?
		WHERE mgmt_client = ? AND key = ? AND req_hash = ?`, resp.Status, resp.ContentType, resp.Body, millis(d.now().Add(ttl)), mgmtClient, key, reqHash)
	if err != nil {
		return fmt.Errorf("complete idempotent: %w", err)
	}
	return nil
}

// AbandonIdempotent は処理中の記録を消す（5xx のとき。同じキーでやり直せるように）。
func (d *DB) AbandonIdempotent(ctx context.Context, mgmtClient, key, reqHash string) error {
	_, err := d.sql.ExecContext(ctx, "DELETE FROM idempotency WHERE mgmt_client = ? AND key = ? AND req_hash = ? AND status = 'pending'", mgmtClient, key, reqHash)
	if err != nil {
		return fmt.Errorf("abandon idempotent: %w", err)
	}
	return nil
}

// PurgeIdempotency は期限の切れた記録を消す（定期の処理）。
func (d *DB) PurgeIdempotency(ctx context.Context) (int64, error) {
	res, err := d.sql.ExecContext(ctx, "DELETE FROM idempotency WHERE expires_at <= ?", millis(d.now()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
