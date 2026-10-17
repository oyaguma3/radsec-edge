package rsconf

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	root := t.TempDir()
	s := Store{Root: root}
	if gen, b, err := s.Current("tenant-a"); err != nil || gen != "" || b != nil {
		t.Fatalf("Current(empty) = %q, %v, %v", gen, b, err)
	}
	b1 := Bundle{FileConf: []byte("conf1"), FileCABundle: []byte("ca"), FileServerCert: []byte("cert"), FileServerKey: []byte("key")}
	g1, err := s.Stage("tenant-a", b1)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidGen(g1) || g1 != GenName(b1) {
		t.Errorf("gen = %q", g1)
	}
	if err := s.Activate("tenant-a", g1); err != nil {
		t.Fatal(err)
	}
	gen, got, err := s.Current("tenant-a")
	if err != nil || gen != g1 || got.Hash() != b1.Hash() {
		t.Fatalf("Current = %q, %v", gen, err)
	}
	// リンクは相対パス（コンテナの中の /conf/current から gen/<版> を指す）。
	target, _ := os.Readlink(filepath.Join(root, "tenant-a", CurrentLink))
	if target != "gen/"+g1 {
		t.Errorf("link = %q", target)
	}
	// 権限: ディレクトリは 0750、ファイルは 0640。
	info, _ := os.Stat(filepath.Join(root, "tenant-a", GenDir, g1, FileServerKey))
	if info.Mode().Perm() != 0o640 {
		t.Errorf("key mode = %v", info.Mode())
	}
	info, _ = os.Stat(filepath.Join(root, "tenant-a", GenDir, g1))
	if info.Mode().Perm() != 0o750 {
		t.Errorf("dir mode = %v", info.Mode())
	}
	// 同じ中身はもう一度書かない。
	if g, err := s.Stage("tenant-a", maps.Clone(b1)); err != nil || g != g1 {
		t.Errorf("Stage(same) = %q, %v", g, err)
	}

	// 版を 4 つ作って、今の版を含めて 3 つ残す。
	var gens []string
	for i := range 4 {
		b := maps.Clone(b1)
		b[FileConf] = []byte{byte('a' + i)}
		g, err := s.Stage("tenant-a", b)
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(time.Duration(i-10) * time.Minute)
		os.Chtimes(filepath.Join(root, "tenant-a", GenDir, g), past, past)
		gens = append(gens, g)
	}
	os.Mkdir(filepath.Join(root, "tenant-a", GenDir, ".tmp-left"), 0o750)
	if err := s.Prune("tenant-a", 3); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "tenant-a", GenDir))
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	// 残るのは今の版（g1）と、新しい 2 つ（gens[3]、gens[2]）。
	want := map[string]bool{g1: true, gens[3]: true, gens[2]: true}
	if len(left) != 3 {
		t.Fatalf("left = %v", left)
	}
	for _, l := range left {
		if !want[l] {
			t.Errorf("unexpected %s left (want %v)", l, want)
		}
	}

	if slugs, _ := s.Slugs(); len(slugs) != 1 || slugs[0] != "tenant-a" {
		t.Errorf("Slugs = %v", slugs)
	}
	if _, err := s.Stage("../x", b1); err == nil {
		t.Error("bad slug accepted")
	}
	if err := s.Activate("tenant-a", "../../etc"); err == nil {
		t.Error("bad gen accepted")
	}
	if err := s.Remove("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tenant-a")); !os.IsNotExist(err) {
		t.Error("tenant dir is left")
	}
}
