package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SeenKind は AP の接続の出来事の種類。
type SeenKind int

const (
	SeenUp     SeenKind = iota // 接続の確立
	SeenDown                   // 切断
	SeenReject                 // 証明書の拒否
)

// SeenEvent は radsecproxy のログから読んだ、AP の接続の出来事。
type SeenEvent struct {
	// AP は AP かグループの名前。Shared なら共通のブロック（IP ごとに記録する）で、AP は空。
	AP     string
	Shared bool
	Kind   SeenKind
	At     time.Time
	// IP は接続元（AP とグループは接続の確立のときだけ、共通のブロックは確立と切断のとき）。
	IP string
}

// Seen は AP の接続の状態。
type Seen struct {
	AP         string
	Connected  bool
	LastUp     time.Time
	LastDown   time.Time
	LastIP     string
	LastReject time.Time
}

// LogCursor はテナントのログをどこまで読んだかを返す（まだ読んでいなければゼロ値）。
func (d *DB) LogCursor(ctx context.Context, tenantID string) (time.Time, error) {
	var s string
	err := d.sql.QueryRowContext(ctx, "SELECT since FROM log_cursors WHERE tenant_id = ?", tenantID).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get log cursor %s: %w", tenantID, err)
	}
	return time.Parse(time.RFC3339Nano, s)
}

// ApplySeen は出来事を時刻の順に当てて AP の接続の状態を書き換え、ログを読んだ位置を since にする（1 つのトランザクション）。
// restarted なら（コンテナを起動し直した後は切断の行が出ないので）共通のブロックの接続の数を数え直す。
func (d *DB) ApplySeen(ctx context.Context, tenantID string, events []SeenEvent, since time.Time, restarted bool) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		if restarted {
			if _, err := tx.ExecContext(ctx, "UPDATE shared_seen SET connections = 0 WHERE tenant_id = ?", tenantID); err != nil {
				return err
			}
		}
		for _, e := range events {
			if e.Shared {
				if err := applySharedSeen(ctx, tx, tenantID, e); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO ap_seen (tenant_id, ap) VALUES (?, ?) ON CONFLICT DO NOTHING", tenantID, e.AP); err != nil {
				return err
			}
			var err error
			switch e.Kind {
			case SeenUp:
				_, err = tx.ExecContext(ctx, "UPDATE ap_seen SET connected = 1, last_up = ?, last_ip = ? WHERE tenant_id = ? AND ap = ?", millis(e.At), e.IP, tenantID, e.AP)
			case SeenDown:
				_, err = tx.ExecContext(ctx, "UPDATE ap_seen SET connected = 0, last_down = ? WHERE tenant_id = ? AND ap = ?", millis(e.At), tenantID, e.AP)
			case SeenReject:
				_, err = tx.ExecContext(ctx, "UPDATE ap_seen SET last_reject = ? WHERE tenant_id = ? AND ap = ?", millis(e.At), tenantID, e.AP)
			}
			if err != nil {
				return err
			}
		}
		// テナントごとに新しい順に上限まで残す（IP は増え続けうるので）。
		if _, err := tx.ExecContext(ctx, `DELETE FROM shared_seen WHERE tenant_id = ?1 AND ip NOT IN (
			SELECT ip FROM shared_seen WHERE tenant_id = ?1 ORDER BY last_up DESC, ip LIMIT ?2)`, tenantID, keepSharedSeen); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO log_cursors (tenant_id, since) VALUES (?, ?) ON CONFLICT (tenant_id) DO UPDATE SET since = excluded.since",
			tenantID, since.UTC().Format(time.RFC3339Nano))
		return err
	})
}

// keepSharedSeen は共通のブロックの接続の記録を残す数（テナントごと。§24.3）。
const keepSharedSeen = 1000

// applySharedSeen は共通のブロックの出来事を送信元の IP の行に当てる。
func applySharedSeen(ctx context.Context, tx *sql.Tx, tenantID string, e SeenEvent) error {
	if e.Kind == SeenReject || e.IP == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO shared_seen (tenant_id, ip) VALUES (?, ?) ON CONFLICT DO NOTHING", tenantID, e.IP); err != nil {
		return err
	}
	var err error
	if e.Kind == SeenUp {
		_, err = tx.ExecContext(ctx, "UPDATE shared_seen SET connections = connections + 1, last_up = ? WHERE tenant_id = ? AND ip = ?", millis(e.At), tenantID, e.IP)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE shared_seen SET connections = max(connections - 1, 0), last_down = ? WHERE tenant_id = ? AND ip = ?", millis(e.At), tenantID, e.IP)
	}
	return err
}

// SharedSeen は共通のブロックの送信元の IP ごとの接続の状態。
type SharedSeen struct {
	IP string
	// Connections は今の接続の数（コンテナの再起動の前の接続は、LastUp が起動より前なので数えない）。
	Connections      int
	LastUp, LastDown time.Time
}

// SharedSeens はテナントの共通のブロックの接続の状態を、最後の接続の新しい順に返す。
func (d *DB) SharedSeens(ctx context.Context, tenantID string) ([]SharedSeen, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT ip, connections, last_up, last_down FROM shared_seen WHERE tenant_id = ? ORDER BY last_up DESC, ip", tenantID)
	if err != nil {
		return nil, fmt.Errorf("list shared seen: %w", err)
	}
	defer rows.Close()
	var out []SharedSeen
	for rows.Next() {
		var s SharedSeen
		var up, down int64
		if err := rows.Scan(&s.IP, &s.Connections, &up, &down); err != nil {
			return nil, err
		}
		s.LastUp, s.LastDown = fromMillis(up), fromMillis(down)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Seen はテナントの AP の接続の状態を、AP の名前から引けるように返す。
func (d *DB) Seen(ctx context.Context, tenantID string) (map[string]Seen, error) {
	rows, err := d.sql.QueryContext(ctx, "SELECT ap, connected, last_up, last_down, last_ip, last_reject FROM ap_seen WHERE tenant_id = ?", tenantID)
	if err != nil {
		return nil, fmt.Errorf("list seen: %w", err)
	}
	defer rows.Close()
	out := map[string]Seen{}
	for rows.Next() {
		var s Seen
		var up, down, rej int64
		if err := rows.Scan(&s.AP, &s.Connected, &up, &down, &s.LastIP, &rej); err != nil {
			return nil, err
		}
		s.LastUp, s.LastDown, s.LastReject = fromMillis(up), fromMillis(down), fromMillis(rej)
		out[s.AP] = s
	}
	return out, rows.Err()
}
