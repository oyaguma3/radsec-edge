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
	AP   string
	Kind SeenKind
	At   time.Time
	// IP は接続元（接続の確立のときだけ）。
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
func (d *DB) ApplySeen(ctx context.Context, tenantID string, events []SeenEvent, since time.Time) error {
	return d.tx(ctx, func(tx *sql.Tx) error {
		for _, e := range events {
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
		_, err := tx.ExecContext(ctx, "INSERT INTO log_cursors (tenant_id, since) VALUES (?, ?) ON CONFLICT (tenant_id) DO UPDATE SET since = excluded.since",
			tenantID, since.UTC().Format(time.RFC3339Nano))
		return err
	})
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
