package audit

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
)

func TestAppendUsesJSTDate(t *testing.T) {
	dir := t.TempDir()
	f := NewFiles(dir, 14)
	// UTC の 15:30 は日本時間の翌日。
	e := db.AuditEntry{Time: time.Date(2026, 10, 31, 15, 30, 0, 0, time.UTC), Operator: "op", MgmtClient: "provisioner", Source: db.SourceAPI,
		Action: "ca.create", Target: "tenant.a", Detail: map[string]any{"serial": "ab"}, TraceID: "t1"}
	if err := f.Append(e); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit-20261101.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"time":"2026-11-01T00:30:00+09:00"`, `"operator":"op"`, `"mgmtClient":"provisioner"`, `"source":"api"`,
		`"action":"ca.create"`, `"target":"tenant.a"`, `"detail":{"serial":"ab"}`, `"traceId":"t1"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("line %s: want %s", b, want)
		}
	}
}

func TestMaintain(t *testing.T) {
	dir := t.TempDir()
	f := NewFiles(dir, 14)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, jst)
	write := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("line\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	today := write("audit-20261031.jsonl", time.Minute)
	yesterday := write("audit-20261030.jsonl", 12*time.Hour)
	justRotated := write("audit-20261029.jsonl", time.Minute) // 書き終わるのを待つ
	old := write("audit-20261016.jsonl", 15*24*time.Hour)
	other := write("notes.txt", 30*24*time.Hour)
	if err := f.Maintain(now); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{today, justRotated, other, yesterday + ".gz"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s should exist: %v", p, err)
		}
	}
	for _, p := range []string{yesterday, old} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s should be gone", p)
		}
	}
	fh, err := os.Open(yesterday + ".gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != "line\n" {
		t.Errorf("gzip content %q", b)
	}
}

func TestCheckWritableDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := CheckWritableDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("left files: %v", entries)
	}
}
