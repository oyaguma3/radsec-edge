// Package db はエッジの SQLite（設計概要 §7.2）を扱う。
//
// スキーマの移行は OSS/BSS と同じ自前の仕組み（版の番号の表と、版ごとの SQL を embed）。
// 書き込みの競合（SQLITE_BUSY）を避けるため、接続は 1 つだけにする（エッジの要求の量は少ない）。
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	// ErrNotFound は対象がないことを表す。
	ErrNotFound = errors.New("not found")
	// ErrConflict は一意の制約（slug、ポート、NAS-Identifier など）に反することを表す。
	ErrConflict = errors.New("conflict")
)

// DB は SQLite への接続。
type DB struct {
	sql *sql.DB
	// now は現在時刻（テストで差し替える）。
	now func() time.Time
}

// Open は SQLite のファイルを開く（なければ作る）。WAL、外部キー、待ち時間を有効にする。
func Open(ctx context.Context, file string) (*DB, error) {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "foreign_keys(1)", "busy_timeout(5000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	d, err := sql.Open("sqlite", "file:"+file+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open db %s: %w", file, err)
	}
	d.SetMaxOpenConns(1)
	d.SetConnMaxIdleTime(0)
	if err := d.PingContext(ctx); err != nil {
		d.Close()
		return nil, fmt.Errorf("open db %s: %w", file, err)
	}
	return &DB{sql: d, now: time.Now}, nil
}

// Close は接続を閉じる。
func (d *DB) Close() error { return d.sql.Close() }

// Ping は DB を使えることを確かめる。
func (d *DB) Ping(ctx context.Context) error {
	var n int
	return d.sql.QueryRowContext(ctx, "SELECT 1").Scan(&n)
}

// SetNow は現在時刻の関数を差し替える（テスト用）。
func (d *DB) SetNow(now func() time.Time) { d.now = now }

// millis は時刻を DB の値（UNIX 時間のミリ秒）にする。ゼロ値は 0。
func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// fromMillis は DB の値を時刻にする。0 はゼロ値。
func fromMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// isUnique は一意の制約に反したエラーか。
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// tx はトランザクションの中で fn を実行する。fn がエラーを返したら戻す。
func (d *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

// migration は 1 つの移行（migrations/NNNN_名前.sql）。
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations は埋め込んだ移行を番号の順に返す。
func loadMigrations() ([]migration, error) {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, f := range files {
		base := strings.TrimSuffix(path.Base(f), ".sql")
		num, name, ok := strings.Cut(base, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v < 1 {
			return nil, fmt.Errorf("migration file name %q: must be NNNN_name.sql", f)
		}
		b, err := migrations.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

// Migrate は、まだ適用していない移行を番号の順に適用し、適用した番号を返す。全体を 1 つのトランザクションで行う
// （途中で失敗したら、何も適用しなかった状態に戻る）。DB にあってこのプログラムが知らない番号があれば、
// 新しい版で移行した DB を古い版で使おうとしているので、エラーにする。
func (d *DB) Migrate(ctx context.Context) ([]int, error) {
	ms, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	applied := []int{}
	err = d.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		) STRICT`); err != nil {
			return fmt.Errorf("create schema_migrations: %w", err)
		}
		rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations")
		if err != nil {
			return err
		}
		var done []int
		for rows.Next() {
			var v int
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return err
			}
			done = append(done, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if latest := ms[len(ms)-1].version; len(done) > 0 && slices.Max(done) > latest {
			return fmt.Errorf("the database schema (version %d) is newer than this program (version %d)", slices.Max(done), latest)
		}
		for _, m := range ms {
			if slices.Contains(done, m.version) {
				continue
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
				m.version, m.name, millis(d.now())); err != nil {
				return err
			}
			applied = append(applied, m.version)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return applied, nil
}

// SchemaVersion は、適用済みの移行のうち最も新しい番号を返す（なければ 0）。
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := d.sql.QueryRowContext(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&v)
	return v, err
}
