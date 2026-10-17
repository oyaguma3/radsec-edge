// Package rsconf は、テナントの radsecproxy の設定とファイル一式（バンドル）を生成する（設計概要 §10.3、§11）。
//
// 設定に入れる値は、すべてここで検証してから text/template に渡す（§11.2）。名前は §8.1 の規則（英小文字・数字・-）、
// 上流は IP アドレスとポート、共有シークレットは決まった文字だけ。`radsecproxy -p` で見つからない誤り
// （client の重複、CRL の欠落、期限の切れた CRL）も、生成するときに確かめる（§18.1 の V3）。
package rsconf

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"text/template"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// バンドルのファイルの名前。radsecproxy のコンテナでは MountDir の下に見える。
const (
	FileConf       = "radsecproxy.conf"
	FileCABundle   = "ca-bundle.pem"
	FileServerCert = "server.pem"
	FileServerKey  = "server.key"
)

// MountDir は、radsecproxy のコンテナの中で今の版のバンドルが見えるディレクトリ（設計概要 §10.2）。
// テナントのディレクトリを /conf にマウントし、その中のシンボリックリンク current が版のディレクトリを指す。
const MountDir = "/conf/current"

// Files はバンドルのファイルの名前（並びは決まった順）。
var Files = []string{FileConf, FileCABundle, FileServerCert, FileServerKey}

// Bundle はテナントの版のファイル一式（ファイルの名前 → 中身）。
type Bundle map[string][]byte

// Input は設定の生成に使う値。
type Input struct {
	Slug      string
	URNPrefix string
	// APs は利用者の AP の名前（ヘルスチェック用の probe は自動で足す）。
	APs []string
	// Auth と Acct は上流の認証と課金、Secret は上流との共有シークレット。
	Auth, Acct netip.AddrPort
	Secret     string
	// ClientCAPEM はテナントのクライアントCA の証明書、CRLPEM はその CRL。
	ClientCAPEM, CRLPEM []byte
	// ServerCertPEM と ServerKeyPEM はテナントのサーバー証明書と鍵。
	ServerCertPEM, ServerKeyPEM []byte
	// Now は CRL の期限を確かめる時刻。
	Now time.Time
}

// secretPattern は共有シークレット（EDGE_UPSTREAM_SECRET）に使える文字。設定ファイルに書くので、空白・引用符・# と、
// radsecproxy が値の中で特別に扱いうる % などの記号は使わせない（base64 と 16 進の値は使える）。
var secretPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=@-]{8,128}$`)

// ValidSecret は共有シークレットが設定ファイルに書ける文字だけか。
func ValidSecret(s string) bool { return secretPattern.MatchString(s) }

//go:embed radsecproxy.conf.tmpl
var confTemplate string

var tmpl = template.Must(template.New("conf").Option("missingkey=error").Parse(confTemplate))

// client は設定の client ブロック（と rewrite ブロック）の 1 つ。
type client struct {
	NASID string
	URI   string
}

type confData struct {
	Slug     string
	Dir      string
	Clients  []client
	AuthHost string
	AuthPort uint16
	AcctHost string
	AcctPort uint16
	Secret   string
}

// Render は設定とファイル一式を生成する。値の検証と、`radsecproxy -p` で見つからない誤りの確認を行う。
func Render(in Input) (Bundle, error) {
	if err := names.CheckTenant(in.Slug); err != nil {
		return nil, fmt.Errorf("テナントの名前: %w", err)
	}
	if err := names.CheckURNPrefix(in.URNPrefix); err != nil {
		return nil, err
	}
	for _, u := range []netip.AddrPort{in.Auth, in.Acct} {
		if !u.IsValid() || u.Port() == 0 || u.Addr().IsUnspecified() || u.Addr().Zone() != "" {
			return nil, errors.New("上流は IP アドレスとポートで与えてください")
		}
	}
	if !ValidSecret(in.Secret) {
		return nil, errors.New("上流の共有シークレットに使えない文字があります")
	}

	// client ブロックは AP の名前の順に並べ、ヘルスチェック用の probe を最後に置く（AP がつなぐたびに、一致するまでの
	// client ブロックの数だけ「一致しない」の行が出るので、接続の少ない probe は後ろにする。§18.1 の V4）。
	aps := slices.Sorted(slices.Values(in.APs))
	seen := map[string]bool{}
	var clients []client
	for _, a := range aps {
		if err := names.CheckAP(a); err != nil {
			return nil, fmt.Errorf("AP の名前 %q: %w", a, err)
		}
		if seen[a] {
			// 同じ名前の client が 2 つあっても `radsecproxy -p` は通る（§18.1 の V3）ので、ここで断る。
			return nil, fmt.Errorf("AP の名前 %q が重なっています", a)
		}
		seen[a] = true
		clients = append(clients, client{NASID: names.NASIdentifier(in.Slug, a), URI: names.SANURI(in.URNPrefix, in.Slug, a)})
	}
	clients = append(clients, client{NASID: names.NASIdentifier(in.Slug, names.ProbeAP), URI: names.SANURI(in.URNPrefix, in.Slug, names.ProbeAP)})

	caBundle, err := caBundle(in.ClientCAPEM, in.CRLPEM, in.Now)
	if err != nil {
		return nil, err
	}
	srv, err := pki.ParseCert(in.ServerCertPEM)
	if err != nil {
		return nil, fmt.Errorf("サーバー証明書: %w", err)
	}
	if !pki.KeyMatches(srv, in.ServerKeyPEM) {
		return nil, errors.New("サーバー証明書と鍵が合いません")
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, confData{
		Slug: in.Slug, Dir: MountDir, Clients: clients,
		AuthHost: hostString(in.Auth.Addr()), AuthPort: in.Auth.Port(),
		AcctHost: hostString(in.Acct.Addr()), AcctPort: in.Acct.Port(),
		Secret: in.Secret,
	})
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return Bundle{
		FileConf:       buf.Bytes(),
		FileCABundle:   caBundle,
		FileServerCert: bytes.Clone(in.ServerCertPEM),
		FileServerKey:  bytes.Clone(in.ServerKeyPEM),
	}, nil
}

// hostString は server ブロックの host の値。IPv6 のアドレスは [] で囲む。
func hostString(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

// caBundle は radsecproxy の CACertificateFile（CA の証明書と CRL を 1 つのファイルに入れたもの。§18.1）を作る。
// CRL がない・CA の署名でない・期限が切れているものは断る（CRLCheck on で CRL がないと、`-p` は通るが全 AP が拒否される。
// 期限の切れた CRL を読み込ませると全接続が切れる。§11.2）。
func caBundle(caPEM, crlPEM []byte, now time.Time) ([]byte, error) {
	ca, err := pki.ParseCert(caPEM)
	if err != nil {
		return nil, fmt.Errorf("クライアントCA の証明書: %w", err)
	}
	if len(bytes.TrimSpace(crlPEM)) == 0 {
		return nil, errors.New("CRL がありません")
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		return nil, err
	}
	if _, err := pki.CheckCRL(crl, ca, nil, now); err != nil {
		return nil, err
	}
	return slices.Concat(pki.EncodeCert(ca.Raw), pki.EncodeCRL(crl.Raw)), nil
}

// Hash はバンドルの中身のハッシュ（16 進）。ファイルの名前と中身を決まった順で入れる。
func (b Bundle) Hash() string { return hashOf(b, slices.Sorted(maps.Keys(b))) }

// restartFiles は、変わったら再起動が要るファイル（client ブロックとサーバー証明書。SIGHUP で読み直すのは CA と CRL だけ。§18.1）。
var restartFiles = []string{FileConf, FileServerCert, FileServerKey}

func hashOf(b Bundle, files []string) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(b[f]))
		h.Write(b[f])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Action は、今の版から新しい版に移るときに radsecproxy に行う操作。
type Action string

const (
	ActionNone    Action = "none"
	ActionSIGHUP  Action = "sighup"
	ActionRestart Action = "restart"
)

// ActionFrom は、old（今の版。なければ nil）から b に移るときの操作を返す。
func (b Bundle) ActionFrom(old Bundle) Action {
	switch {
	case old == nil || hashOf(old, restartFiles) != hashOf(b, restartFiles):
		return ActionRestart
	case !bytes.Equal(old[FileCABundle], b[FileCABundle]):
		return ActionSIGHUP
	default:
		return ActionNone
	}
}

// Trust はバンドルの CA の証明書と CRL を返す。
func (b Bundle) Trust() (*x509.Certificate, *x509.RevocationList, error) {
	var ca *x509.Certificate
	var crl *x509.RevocationList
	rest := b[FileCABundle]
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		var err error
		switch blk.Type {
		case "CERTIFICATE":
			ca, err = x509.ParseCertificate(blk.Bytes)
		case "X509 CRL":
			crl, err = x509.ParseRevocationList(blk.Bytes)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	if ca == nil || crl == nil {
		return nil, nil, errors.New("CA のファイルに CA の証明書と CRL がありません")
	}
	return ca, crl, nil
}

// WithCRL は、CRL だけを crlPEM に入れ替えたバンドルを返す（CRL の更新。設計概要 §9.5）。
// CRL はバンドルの CA の署名で、期限が切れておらず、番号が今の CRL より小さくないものに限る。
func (b Bundle) WithCRL(crlPEM []byte, now time.Time) (Bundle, error) {
	ca, cur, err := b.Trust()
	if err != nil {
		return nil, err
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		return nil, err
	}
	if _, err := pki.CheckCRL(crl, ca, cur.Number, now); err != nil {
		return nil, err
	}
	out := maps.Clone(b)
	out[FileCABundle] = slices.Concat(pki.EncodeCert(ca.Raw), pki.EncodeCRL(crl.Raw))
	return out, nil
}
