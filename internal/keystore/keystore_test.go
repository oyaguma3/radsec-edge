package keystore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStore(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if k, err := s.Current("tenant-a", Server); err != nil || k != nil {
		t.Fatalf("Current(empty) = %q, %v", k, err)
	}
	k1, err := s.NewPending("tenant-a", Server)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(s.Dir, "tenant-a", "server.pending.key"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode())
	}
	k2, _ := s.NewPending("tenant-a", Server)
	if bytes.Equal(k1, k2) {
		t.Error("NewPending returned the same key")
	}
	if p, _ := s.Pending("tenant-a", Server); !bytes.Equal(p, k2) {
		t.Error("Pending is not the latest key")
	}
	if err := s.Promote("tenant-a", Server); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Current("tenant-a", Server); !bytes.Equal(c, k2) {
		t.Error("Current is not the promoted key")
	}
	if p, _ := s.Pending("tenant-a", Server); p != nil {
		t.Error("Pending is left after Promote")
	}
	if c, _ := s.Current("tenant-a", Probe); c != nil {
		t.Error("probe key exists")
	}
	if _, err := s.NewPending("../x", Server); err == nil {
		t.Error("bad id accepted")
	}
	if err := s.Remove("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Current("tenant-a", Server); c != nil {
		t.Error("key is left after Remove")
	}
}
