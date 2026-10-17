package names

import (
	"errors"
	"slices"
	"testing"
)

func TestCheckTenantAndAP(t *testing.T) {
	ok := []string{"a", "0", "tenant-a", "ap-001", "a1-b2", "12345", "abcdefghijklmnopqrstuvwxyz012345"}
	for _, s := range ok {
		if err := CheckTenant(s); err != nil {
			t.Errorf("CheckTenant(%q) = %v", s, err)
		}
		if err := CheckAP(s); err != nil {
			t.Errorf("CheckAP(%q) = %v", s, err)
		}
	}
	// 設定ファイルの構文や正規表現の記号、大文字、長すぎる名前、先頭・末尾の - は断る。
	bad := []string{"", "-a", "a-", "A", "tenant_a", "a.b", "a b", "a$", "a'", "a\nb", "a}", "a*", "a/b",
		"abcdefghijklmnopqrstuvwxyz0123456", "テナント"}
	for _, s := range bad {
		if err := CheckTenant(s); !errors.Is(err, ErrSlug) {
			t.Errorf("CheckTenant(%q) = %v, want ErrSlug", s, err)
		}
		if err := CheckAP(s); !errors.Is(err, ErrSlug) {
			t.Errorf("CheckAP(%q) = %v, want ErrSlug", s, err)
		}
	}
	if err := CheckAP(ProbeAP); !errors.Is(err, ErrProbe) {
		t.Errorf("CheckAP(probe) = %v, want ErrProbe", err)
	}
	if err := CheckTenant(ProbeAP); err != nil {
		t.Errorf("CheckTenant(probe) = %v（テナントの名前としては使える）", err)
	}
}

func TestCheckDomainAndPrefix(t *testing.T) {
	for _, d := range []string{"radsec.example.net", "a.b", "radsec-1.example.net"} {
		if err := CheckDomain(d); err != nil {
			t.Errorf("CheckDomain(%q) = %v", d, err)
		}
	}
	for _, d := range []string{"", "example", ".example.net", "example.net.", "a..b", "*.example.net", "Example.net", "a_b.net", "-a.net"} {
		if err := CheckDomain(d); err == nil {
			t.Errorf("CheckDomain(%q) = nil", d)
		}
	}
	if err := CheckURNPrefix("example"); err != nil {
		t.Error(err)
	}
	for _, p := range []string{"", "ex:ample", "ex.ample", "Example"} {
		if err := CheckURNPrefix(p); err == nil {
			t.Errorf("CheckURNPrefix(%q) = nil", p)
		}
	}
}

func TestDerived(t *testing.T) {
	if got := NASIdentifier("tenant-a", "ap-001"); got != "tenant-a-ap-001" {
		t.Errorf("NASIdentifier = %q", got)
	}
	if got := SANURI("example", "tenant-a", "ap-001"); got != "urn:example:nas:tenant-a:ap-001" {
		t.Errorf("SANURI = %q", got)
	}
	want := []string{"primary.tenant-a.radsec.example.net", "secondary.tenant-a.radsec.example.net", "tertiary.tenant-a.radsec.example.net"}
	if got := SlotNames("tenant-a", "radsec.example.net"); !slices.Equal(got, want) {
		t.Errorf("SlotNames = %v", got)
	}
}
