package certs

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestEnsureFilesGenerates(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "cert.pem")
	keyPath := filepath.Join(dir, "tls", "key.pem")

	created, err := EnsureFiles(certPath, keyPath, []string{"gui.example.ts.net", "100.64.0.1"})
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if ki.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %v", ki.Mode().Perm())
	}

	f, err := LoadFile(certPath, keyPath, discard)
	if err != nil {
		t.Fatal(err)
	}
	leaf := f.Leaf()
	if !slices.Equal(leaf.DNSNames, []string{"gui.example.ts.net"}) {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("100.64.0.1")) {
		t.Errorf("IPAddresses = %v", leaf.IPAddresses)
	}

	// 2 回目は生成せず、既存のものを使う。
	created, err = EnsureFiles(certPath, keyPath, nil)
	if err != nil || created {
		t.Fatalf("second: created=%v err=%v", created, err)
	}
	f2, err := LoadFile(certPath, keyPath, discard)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(f2.Leaf()) != Fingerprint(leaf) {
		t.Error("certificate changed on second call")
	}
}

func TestEnsureFilesPartial(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureFiles(certPath, keyPath, nil); err == nil {
		t.Error("only cert exists: want error")
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("key must not be generated")
	}
}

func writePair(t *testing.T, certPath, keyPath string, host string) {
	t.Helper()
	certPEM, keyPEM, err := SelfSigned("test", []string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writePair(t, certPath, keyPath, "old.example")

	f, err := LoadFile(certPath, keyPath, discard)
	if err != nil {
		t.Fatal(err)
	}
	old := Fingerprint(f.Leaf())

	// 変更がなければそのまま。
	f.reloadIfChanged()
	if Fingerprint(f.Leaf()) != old {
		t.Fatal("reloaded without change")
	}

	// 秘密鍵が対応しない途中の状態では、それまでの証明書を使い続ける。
	certPEM, _, err := SelfSigned("test", []string{"new.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f.reloadIfChanged()
	if Fingerprint(f.Leaf()) != old {
		t.Fatal("mismatched pair must not be loaded")
	}

	// 両方そろえば読み直す。
	writePair(t, certPath, keyPath, "new.example")
	f.reloadIfChanged()
	if got := f.Leaf().DNSNames; !slices.Equal(got, []string{"new.example"}) {
		t.Errorf("after reload DNSNames = %v", got)
	}

	// GetCertificate は確認間隔が過ぎるまでファイルを見ない。
	writePair(t, certPath, keyPath, "newer.example")
	cert, err := f.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.Leaf.DNSNames, []string{"new.example"}) {
		t.Errorf("GetCertificate before interval: DNSNames = %v", cert.Leaf.DNSNames)
	}
	f.mu.Lock()
	f.checkedAt = time.Now().Add(-checkInterval)
	f.mu.Unlock()
	if cert, _ = f.GetCertificate(nil); !slices.Equal(cert.Leaf.DNSNames, []string{"newer.example"}) {
		t.Errorf("GetCertificate after interval: DNSNames = %v", cert.Leaf.DNSNames)
	}
}

func TestReplaceAndReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	if _, err := EnsureFiles(certPath, keyPath, []string{"radsec-edge"}); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	before := Fingerprint(f.Leaf())
	if _, err := Replace(certPath, keyPath, []string{"radsec-edge", "edge.example.net"}); err != nil {
		t.Fatal(err)
	}
	if Fingerprint(f.Leaf()) != before {
		t.Error("replaced without reload")
	}
	if err := f.Reload(); err != nil {
		t.Fatal(err)
	}
	if Fingerprint(f.Leaf()) == before || len(f.Leaf().DNSNames) != 2 {
		t.Errorf("after reload: %v", f.Leaf().DNSNames)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", info, err)
	}
	// 壊れたファイルでは今の証明書のまま続け、誤りを返す。
	cur := Fingerprint(f.Leaf())
	if err := os.WriteFile(certPath, []byte("broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.Reload(); err == nil {
		t.Error("broken file reloaded")
	}
	if Fingerprint(f.Leaf()) != cur {
		t.Error("the certificate changed")
	}
}
