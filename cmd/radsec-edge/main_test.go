package main

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/db"
)

// 単独モードで作ったテナント（数字でない ID）があれば、管理モードで起動しない（設計概要 §24.11 の EA4）。
func TestCheckManagedTenants(t *testing.T) {
	ctx := t.Context()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := checkManagedTenants(ctx, d); err != nil {
		t.Errorf("empty: %v", err)
	}
	spec := db.TenantSpec{ID: "42", Slug: "tenant-a", Port: 20042, AuthUpstream: netip.MustParseAddrPort("10.0.0.1:1812"), AcctUpstream: netip.MustParseAddrPort("10.0.0.1:1813")}
	if _, err := d.CreateTenant(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := checkManagedTenants(ctx, d); err != nil {
		t.Errorf("numeric id: %v", err)
	}
	spec.ID, spec.Slug, spec.Port = "tenant-b", "tenant-b", 20043
	if _, err := d.CreateTenant(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := checkManagedTenants(ctx, d); err == nil || !strings.Contains(err.Error(), "tenant-b") {
		t.Errorf("standalone tenant: %v", err)
	}
}
