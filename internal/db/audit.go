package db

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
)

// 監査ログの出どころ（AuditEntry.Source）。
const (
	SourceGUI    = "gui"
	SourceAPI    = "api"
	SourceSystem = "system"
)

// AuditEntry は監査ログの 1 件。Detail に鍵や共有シークレットを入れてはならない。
type AuditEntry struct {
	ID int64
	// Time は書き込むときに DB が決める（読み出しで入る）。
	Time time.Time
	// Operator は GUI の利用者のメールアドレス、または X-Operator-Id。
	Operator string
	Source   string
	Action   string
	Target   string
	Detail   map[string]any
	TraceID  string
	Remote   string
}

// InsertAudit は監査ログを 1 件書き込む。
func (d *DB) InsertAudit(ctx context.Context, e AuditEntry) error {
	detail := []byte("{}")
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail, json.Deterministic(true))
		if err != nil {
			return fmt.Errorf("insert audit: encode detail: %w", err)
		}
		detail = b
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO audit (time, operator, source, action, target, detail, trace_id, remote)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, millis(d.now()), e.Operator, e.Source, e.Action, e.Target, string(detail), e.TraceID, e.Remote)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

// ListAudit は監査ログを新しい順に返す。before が 0 でなければ、その ID より古いものだけ。
func (d *DB) ListAudit(ctx context.Context, before int64, limit int) ([]AuditEntry, error) {
	q := "SELECT id, time, operator, source, action, target, detail, trace_id, remote FROM audit"
	args := []any{}
	if before > 0 {
		q += " WHERE id < ?"
		args = append(args, before)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var t int64
		var detail string
		if err := rows.Scan(&e.ID, &t, &e.Operator, &e.Source, &e.Action, &e.Target, &detail, &e.TraceID, &e.Remote); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.Time = fromMillis(t)
		if err := json.Unmarshal([]byte(detail), &e.Detail); err != nil {
			return nil, fmt.Errorf("list audit: decode detail of %d: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
