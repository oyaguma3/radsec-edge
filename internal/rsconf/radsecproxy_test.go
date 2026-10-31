package rsconf

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

// testImage は結合の試験に使う radsecproxy のイメージ（images/radsecproxy から作る）。
const testImage = "radsec-edge/radsecproxy:1.11.4-pc1"

// radsecproxyCheck は、本物の radsecproxy の `-p`（構文検査）でバンドルを確かめる。
// EDGE_TEST_DOCKER=1 のときだけ動かす（Docker とイメージが要る。CI では必ず動かす）。
func radsecproxyCheck(t *testing.T, b Bundle) (string, error) {
	t.Helper()
	if os.Getenv("EDGE_TEST_DOCKER") != "1" {
		t.Skip("EDGE_TEST_DOCKER=1 のときだけ動かす")
	}
	s := Store{Root: t.TempDir()}
	gen, err := s.Stage("tenant-a", b)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := s.GenPath("tenant-a", gen)
	// ファイルは試験を動かす利用者のものなので、同じ UID で動かす。
	out, err := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network", "none",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", dir+":"+MountDir+":ro", testImage, "radsecproxy", "-p", "-c", MountDir+"/"+FileConf).CombinedOutput()
	return string(out), err
}

func TestRadsecproxyAccepts(t *testing.T) {
	f := newFixture(t)
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := radsecproxyCheck(t, b); err != nil {
		t.Fatalf("radsecproxy -p: %v\n%s", err, out)
	}
}

// AP・グループ・持ち込みの CA・送信元の範囲（IPv6 を含む）・刻印を混ぜた設定と、CRLCheck off の設定を、本物の radsecproxy が受け付けること。
func TestRadsecproxyAcceptsMixed(t *testing.T) {
	f := newFixture(t)
	groupAndBrought(t, f)
	f.in.SourceCIDRs = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	f.in.ProbeCIDRs = []netip.Prefix{netip.MustParsePrefix("172.31.83.0/24")}
	f.in.SharedMatch = Match{Attr: "SubjectAltName:URI", Pattern: "^urn:vendor:[a-z]+$"}
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := radsecproxyCheck(t, b); err != nil {
		t.Fatalf("radsecproxy -p: %v\n%s\n%s", err, out, b[FileConf])
	}
	f = newFixture(t)
	none := pkitest.NewCA(t, "vendor none")
	f.in.Brought = []BroughtCA{{ID: "a", CertPEM: none.PEM}}
	f.in.SharedMatch = Match{Attr: "CN", Pattern: "^[0-9a-f]{12}$"}
	if b, err = Render(f.in); err != nil {
		t.Fatal(err)
	}
	if out, err := radsecproxyCheck(t, b); err != nil {
		t.Fatalf("radsecproxy -p (CRLCheck off): %v\n%s\n%s", err, out, b[FileConf])
	}
}

// 壊れた設定は `-p` が断ること（試験の仕組みそのものの確かめ）。
func TestRadsecproxyRejectsBroken(t *testing.T) {
	f := newFixture(t)
	b, err := Render(f.in)
	if err != nil {
		t.Fatal(err)
	}
	b[FileConf] = []byte(strings.Replace(string(b[FileConf]), "rewriteIn nasid-tenant-a-ap-001", "rewriteIn nosuch", 1))
	if out, err := radsecproxyCheck(t, b); err == nil {
		t.Fatalf("radsecproxy -p accepted a broken config:\n%s", out)
	}
}
