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
	"strconv"
	"strings"
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

// Stamp はテナントの刻印の VSA（設計概要 §24.2）。
type Stamp struct {
	VendorID, VendorType int
}

// BroughtCA はテナントの持ち込みの CA（§24.3）。
type BroughtCA struct {
	// ID は radsec-ca の CA の ID（並びを決めるのに使う）。
	ID string
	// CertPEM は CA の証明書、CRLPEM はその CRL（HasCRL のときだけ）。
	CertPEM, CRLPEM []byte
	// HasCRL は CRL があるか。ない CA があると、テナント全体が CRLCheck off になる。
	HasCRL bool
}

// Match は共通のブロックの照合の形（§24.3）。Attr が空なら条件なし。
type Match struct {
	Attr, Pattern string
}

// Input は設定の生成に使う値。
type Input struct {
	Slug string
	// TenantID は刻印の値（管理モードでは OSS/BSS のテナントの番号、単独モードでは slug。§24.2）。
	TenantID  string
	URNPrefix string
	Stamp     Stamp
	// APs は利用者の AP の名前（ヘルスチェック用の probe は自動で足す）。Groups はグループの名前（§24.3）。
	APs, Groups []string
	// Auth と Acct は上流の認証と課金、Secret は上流との共有シークレット。
	Auth, Acct netip.AddrPort
	Secret     string
	// ClientCAPEM はテナントのクライアントCA（発行した CA）の証明書、CRLPEM はその CRL。
	ClientCAPEM, CRLPEM []byte
	// Brought は持ち込みの CA（任意）。SharedMatch は共通のブロックの照合の形。
	Brought     []BroughtCA
	SharedMatch Match
	// SourceCIDRs は許す送信元の範囲（空なら制限なし）。ProbeCIDRs はヘルスチェックの送信元（テナントのネットワークのサブネット）で、
	// SourceCIDRs があるときに要る。
	SourceCIDRs, ProbeCIDRs []netip.Prefix
	// ServerCertPEM と ServerKeyPEM はテナントのサーバー証明書と鍵。
	ServerCertPEM, ServerKeyPEM []byte
	// Now は CRL の期限を確かめる時刻。
	Now time.Time
}

// MaxSourceCIDRs は送信元の範囲の数の上限。
const MaxSourceCIDRs = 32

// secretPattern は共有シークレット（EDGE_UPSTREAM_SECRET）に使える文字。設定ファイルに書くので、空白・引用符・# と、
// radsecproxy が値の中で特別に扱いうる % などの記号は使わせない（base64 と 16 進の値は使える）。
var secretPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=@-]{8,128}$`)

// ValidSecret は共有シークレットが設定ファイルに書ける文字だけか。
func ValidSecret(s string) bool { return secretPattern.MatchString(s) }

//go:embed radsecproxy.conf.tmpl
var confTemplate string

var tmpl = template.Must(template.New("conf").Option("missingkey=error").Parse(confTemplate))

// block は設定の client ブロックと rewrite ブロックの組。
type block struct {
	// Name は client ブロックの名前、Rewrite は rewrite ブロックの名前。
	Name, Rewrite string
	// NAS は NAS-Identifier の値。Replace なら置き換え（AP と probe）、そうでなければ AP が送らなかったときだけ補う
	// （グループと共通のブロック。§24.3）。
	NAS     string
	Replace bool
	Hosts   []string
	// Match は matchCertificateAttribute の値（空なら条件なし）。
	Match string
}

type confData struct {
	Slug                 string
	TenantID             string
	Dir                  string
	CRLCheck             bool
	PartialChain         bool
	VendorID, VendorType int
	Blocks               []block
	AuthHost             string
	AuthPort             uint16
	AcctHost             string
	AcctPort             uint16
	Secret               string
}

// SharedBlock は共通のブロックの名前。GroupBlock はグループのブロックの名前（§24.4）。
const SharedBlock = "shared"

// GroupBlock はグループの client ブロックの名前。
func GroupBlock(group string) string { return "grp-" + group }

// sharedMatchAttrs は共通のブロックで照合に使える属性。
var sharedMatchAttrs = []string{"CN", "SubjectAltName:URI", "SubjectAltName:DNS"}

// sharedPatternChars は照合の正規表現に使える文字。設定ファイルに入る値なので、空白・改行・/・#・引用符は使わせない。
var sharedPatternChars = regexp.MustCompile(`^[A-Za-z0-9^$.*+?()\[\]{}|\\:_@=-]+$`)

// maxSharedPattern は照合の正規表現の長さの上限。
const maxSharedPattern = 128

// CheckMatch は共通のブロックの照合の形を確かめる（§24.3）。radsecproxy の正規表現は POSIX の拡張正規表現なので、Go では通っても
// 意味の変わる書き方（\\d などの英数字のエスケープ、(? の拡張）は断る。部分一致で意図しない証明書に合わないよう、^ と $ を必須にする。
func CheckMatch(m Match) error {
	if !slices.Contains(sharedMatchAttrs, m.Attr) {
		return fmt.Errorf("照合の属性は %s のどれかにしてください", strings.Join(sharedMatchAttrs, "・"))
	}
	p := m.Pattern
	if len(p) > maxSharedPattern || !sharedPatternChars.MatchString(p) {
		return fmt.Errorf("照合の正規表現は %d 文字までで、英数字と ^$.*+?()[]{}|\\:_@=- だけにしてください", maxSharedPattern)
	}
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		return errors.New("照合の正規表現は ^ で始めて $ で終えてください（部分一致を防ぐため）")
	}
	if strings.Contains(p, "(?") || regexp.MustCompile(`\\[A-Za-z0-9]`).MatchString(p) {
		return errors.New("照合の正規表現に (? と \\d などの英数字のエスケープは使えません（POSIX の拡張正規表現で書いてください）")
	}
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("照合の正規表現が読めません: %w", err)
	}
	return nil
}

// hostOfPrefix は client ブロックの host の値。IPv6 のアドレスは [] で囲む。
func hostOfPrefix(p netip.Prefix) string {
	p = p.Masked()
	if p.Addr().Is6() && !p.Addr().Is4In6() {
		return "[" + p.Addr().String() + "]/" + strconv.Itoa(p.Bits())
	}
	return p.Addr().Unmap().String() + "/" + strconv.Itoa(p.Bits())
}

func hostsOf(ps []netip.Prefix) []string {
	var out []string
	for _, p := range ps {
		out = append(out, hostOfPrefix(p))
	}
	return out
}

// Render は設定とファイル一式を生成する。値の検証と、`radsecproxy -p` で見つからない誤りの確認を行う。
func Render(in Input) (Bundle, error) {
	if err := names.CheckTenant(in.Slug); err != nil {
		return nil, fmt.Errorf("テナントの名前: %w", err)
	}
	if !names.ValidSlug(in.TenantID) {
		return nil, fmt.Errorf("テナントの ID: %w", names.ErrSlug)
	}
	if err := names.CheckURNPrefix(in.URNPrefix); err != nil {
		return nil, err
	}
	if in.Stamp.VendorID < 1 || in.Stamp.VendorID > 16777215 || in.Stamp.VendorType < 1 || in.Stamp.VendorType > 255 {
		return nil, errors.New("刻印の Vendor-Id は 1〜16777215、Vendor-Type は 1〜255 にしてください")
	}
	for _, u := range []netip.AddrPort{in.Auth, in.Acct} {
		if !u.IsValid() || u.Port() == 0 || u.Addr().IsUnspecified() || u.Addr().Zone() != "" {
			return nil, errors.New("上流は IP アドレスとポートで与えてください")
		}
	}
	if !ValidSecret(in.Secret) {
		return nil, errors.New("上流の共有シークレットに使えない文字があります")
	}

	// 送信元の範囲。ヘルスチェックのブロックは顧客の範囲にせず、テナントのネットワークのサブネットだけを許す（エッジのヘルスチェックは
	// 内部から来るので、顧客の範囲にすると反映が必ず失敗する。ヘルスチェックの証明書はエッジの外に出ない。§24.3）。
	hosts, probeHosts := []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}
	if len(in.SourceCIDRs) > 0 {
		if len(in.SourceCIDRs) > MaxSourceCIDRs {
			return nil, fmt.Errorf("送信元の範囲は %d 個までにしてください", MaxSourceCIDRs)
		}
		if len(in.ProbeCIDRs) == 0 {
			return nil, errors.New("テナントのネットワークのサブネットが分からないので、送信元の範囲を設定できません")
		}
		hosts, probeHosts = hostsOf(in.SourceCIDRs), hostsOf(in.ProbeCIDRs)
	}

	// 束（CA と CRL）と CRLCheck・PartialChain を決める。自己署名かは入力を信じず、証明書から判定する（§24.5）。
	trust, err := buildTrust(in)
	if err != nil {
		return nil, err
	}

	// ブロックは AP（名前の順）、グループ（名前の順）、probe、共通の順に並べる（§24.4）。共通のブロックはどの証明書にも合いうるので
	// 必ず最後に置く。AP がつなぐたびに、一致するまでのブロックの数だけ「一致しない」の行が出るので、接続の少ない probe は後ろにする。
	seen := map[string]bool{}
	var blocks []block
	for _, a := range slices.Sorted(slices.Values(in.APs)) {
		if err := names.CheckAP(a); err != nil {
			return nil, fmt.Errorf("AP の名前 %q: %w", a, err)
		}
		if seen[a] {
			// 同じ名前の client が 2 つあっても `radsecproxy -p` は通る（§18.1 の V3）ので、ここで断る。
			return nil, fmt.Errorf("AP の名前 %q が重なっています", a)
		}
		seen[a] = true
		nas := names.NASIdentifier(in.Slug, a)
		blocks = append(blocks, block{Name: nas, Rewrite: "nasid-" + nas, NAS: nas, Replace: true, Hosts: hosts,
			Match: "SubjectAltName:URI:/^" + names.SANURI(in.URNPrefix, in.Slug, a) + "$/"})
	}
	for _, g := range slices.Sorted(slices.Values(in.Groups)) {
		if err := names.CheckGroup(g); err != nil {
			return nil, fmt.Errorf("グループの名前 %q: %w", g, err)
		}
		if seen[g] {
			return nil, fmt.Errorf("グループの名前 %q が重なっています", g)
		}
		seen[g] = true
		blocks = append(blocks, block{Name: GroupBlock(g), Rewrite: GroupBlock(g), NAS: names.NASIdentifier(in.Slug, g), Hosts: hosts,
			Match: "SubjectAltName:URI:/^" + names.GroupSANURI(in.URNPrefix, in.Slug, g) + "$/"})
	}
	probeNAS := names.NASIdentifier(in.Slug, names.ProbeAP)
	blocks = append(blocks, block{Name: probeNAS, Rewrite: "nasid-" + probeNAS, NAS: probeNAS, Replace: true, Hosts: probeHosts,
		Match: "SubjectAltName:URI:/^" + names.SANURI(in.URNPrefix, in.Slug, names.ProbeAP) + "$/"})
	if len(in.Brought) > 0 {
		shared := block{Name: SharedBlock, Rewrite: SharedBlock, NAS: in.Slug, Hosts: hosts}
		switch {
		case in.SharedMatch.Attr != "" || in.SharedMatch.Pattern != "":
			if err := CheckMatch(in.SharedMatch); err != nil {
				return nil, err
			}
			shared.Match = in.SharedMatch.Attr + ":/" + in.SharedMatch.Pattern + "/"
		case !trust.crlCheck:
			// CRLCheck off では失効させた証明書も TLS を通るので、絞らないと、ブロックを消したこちらの証明書が共通のブロックで受け入れられる。
			return nil, errors.New("CRL のない持ち込みの CA があるときは、共通のブロックの照合の形が要ります")
		}
		blocks = append(blocks, shared)
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
		Slug: in.Slug, TenantID: in.TenantID, Dir: MountDir, CRLCheck: trust.crlCheck, PartialChain: trust.partialChain,
		VendorID: in.Stamp.VendorID, VendorType: in.Stamp.VendorType, Blocks: blocks,
		AuthHost: hostString(in.Auth.Addr()), AuthPort: in.Auth.Port(),
		AcctHost: hostString(in.Acct.Addr()), AcctPort: in.Acct.Port(),
		Secret: in.Secret,
	})
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return Bundle{
		FileConf:       buf.Bytes(),
		FileCABundle:   trust.bundle,
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

// trustSet は束と、束から決まる tls ブロックの設定。
type trustSet struct {
	bundle                 []byte
	crlCheck, partialChain bool
}

// buildTrust は radsecproxy の CACertificateFile（CA の証明書と CRL を 1 つのファイルに入れたもの。§18.1）を作る。
//   - 発行した CA の CRL は、なければ・CA の署名でなければ・期限が切れていれば断る（CRLCheck on で CRL がないと、`-p` は通るが
//     その CA の AP が拒否される。期限の切れた CRL を読み込ませると、その CA の接続が切れる。§11.2）。
//   - 持ち込みの CA の CRL は、期限が切れていても断らない。束の中の 1 つの CA の CRL が切れても、ほかの CA の AP は巻き込まれない
//     （aka-mvpset の verify/r11）ので、こちらの AP の追加や失効の反映を止めない（§24.5）。
//   - CRL のない持ち込みの CA があると CRLCheck off にし、束に CRL を入れない（効かない CRL の更新で SIGHUP を起こさない）。
//   - 同じ Subject の CA を 2 つ束に入れると、片方の CA の正当な AP が拒否されるので断る（verify/r11）。
func buildTrust(in Input) (trustSet, error) {
	ca, err := pki.ParseCert(in.ClientCAPEM)
	if err != nil {
		return trustSet{}, fmt.Errorf("クライアントCA の証明書: %w", err)
	}
	t := trustSet{crlCheck: true}
	for _, b := range in.Brought {
		if !b.HasCRL {
			t.crlCheck = false
		}
	}
	subjects := map[string]string{string(ca.RawSubject): "クライアントCA"}
	var parts [][]byte
	parts = append(parts, pki.EncodeCert(ca.Raw))
	if t.crlCheck {
		if len(bytes.TrimSpace(in.CRLPEM)) == 0 {
			return trustSet{}, errors.New("CRL がありません")
		}
		crl, err := pki.ParseCRL(in.CRLPEM)
		if err != nil {
			return trustSet{}, err
		}
		if _, err := pki.CheckCRL(crl, ca, pki.Previous{}, in.Now); err != nil {
			return trustSet{}, err
		}
		parts = append(parts, pki.EncodeCRL(crl.Raw))
	}
	brought := slices.Clone(in.Brought)
	slices.SortFunc(brought, func(a, b BroughtCA) int { return strings.Compare(a.ID, b.ID) })
	for _, b := range brought {
		c, err := pki.ParseCert(b.CertPEM)
		if err != nil {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s の証明書: %w", b.ID, err)
		}
		if err := pki.CheckBroughtCA(c, b.HasCRL, time.Time{}); err != nil {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s: %w", b.ID, err)
		}
		if other, dup := subjects[string(c.RawSubject)]; dup {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s の Subject が %s と同じです（同じ Subject の CA は束に並べられません）", b.ID, other)
		}
		subjects[string(c.RawSubject)] = b.ID
		if !pki.IsSelfSigned(c) {
			t.partialChain = true
		}
		parts = append(parts, pki.EncodeCert(c.Raw))
		if !t.crlCheck {
			continue
		}
		if len(bytes.TrimSpace(b.CRLPEM)) == 0 {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s の CRL がありません", b.ID)
		}
		crl, err := pki.ParseCRL(b.CRLPEM)
		if err != nil {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s の CRL: %w", b.ID, err)
		}
		if err := pki.CheckCRLSignature(crl, c); err != nil {
			return trustSet{}, fmt.Errorf("持ち込みの CA %s の CRL: %w", b.ID, err)
		}
		parts = append(parts, pki.EncodeCRL(crl.Raw))
	}
	t.bundle = slices.Concat(parts...)
	return t, nil
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

// TrustEntry は束の中の CA とその CRL（CRLCheck off なら CRL は nil）。先頭は発行した CA。
type TrustEntry struct {
	CA  *x509.Certificate
	CRL *x509.RevocationList
}

// Trust はバンドルの CA の証明書と CRL を、束に書いた順に返す。
func (b Bundle) Trust() ([]TrustEntry, error) {
	var out []TrustEntry
	rest := b[FileCABundle]
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, TrustEntry{CA: c})
		case "X509 CRL":
			if len(out) == 0 {
				return nil, errors.New("CA のファイルの先頭が CA の証明書ではありません")
			}
			crl, err := x509.ParseRevocationList(blk.Bytes)
			if err != nil {
				return nil, err
			}
			out[len(out)-1].CRL = crl
		}
	}
	if len(out) == 0 {
		return nil, errors.New("CA のファイルに CA の証明書がありません")
	}
	return out, nil
}

// IssuedCRLExpired は、発行した CA（束の先頭）の CRL の期限が切れているか。読み込ませると、こちらの AP の接続が切れる（§11.2）。
func (b Bundle) IssuedCRLExpired(now time.Time) (bool, error) {
	entries, err := b.Trust()
	if err != nil {
		return false, err
	}
	crl := entries[0].CRL
	return crl != nil && !now.Before(crl.NextUpdate), nil
}

// WithCRL は、crlPEM の発行者の CA の CRL だけを入れ替えたバンドルを返す（CRL の更新。設計概要 §9.5）。
// CRL は CA の署名で、期限が切れておらず、今の CRL より古くないものに限る。CRLCheck off の束には CRL を入れないので、そのまま返す。
// ほかの CA の CRL が切れていても入れ替える（失効の反映を優先する。§24.5）。
func (b Bundle) WithCRL(crlPEM []byte, now time.Time) (Bundle, error) {
	entries, err := b.Trust()
	if err != nil {
		return nil, err
	}
	crl, err := pki.ParseCRL(crlPEM)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(entries, func(e TrustEntry) bool { return bytes.Equal(e.CA.RawSubject, crl.RawIssuer) })
	if i < 0 {
		return nil, errors.New("CRL の発行者が束の中にありません")
	}
	e := entries[i]
	if e.CRL == nil {
		return maps.Clone(b), nil
	}
	if _, err := pki.CheckCRL(crl, e.CA, pki.Previous{Number: e.CRL.Number, ThisUpdate: e.CRL.ThisUpdate}, now); err != nil {
		return nil, err
	}
	entries[i].CRL = crl
	var parts [][]byte
	for _, x := range entries {
		parts = append(parts, pki.EncodeCert(x.CA.Raw))
		if x.CRL != nil {
			parts = append(parts, pki.EncodeCRL(x.CRL.Raw))
		}
	}
	out := maps.Clone(b)
	out[FileCABundle] = slices.Concat(parts...)
	return out, nil
}
