// Package config は環境変数（接頭辞 EDGE_）から設定を読む（設計概要 §4）。
package config

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// モード（設計概要 §6）。
const (
	ModeStandalone = "standalone"
	ModeManaged    = "managed"
)

// ポートの範囲（設計概要 §4、§8.1）。テナントに 1 つずつ割り当てる。
const (
	PortMin = 20000
	PortMax = 21999
)

// テナントの刻印の既定（RFC 5612 の文書用の Vendor-Id。実運用では IANA から取得した PEN。設計概要 §24.2）。
const (
	defaultStampVendorID   = 32473
	defaultStampVendorType = 1
)

// Config は radsec-edge の設定。
type Config struct {
	// Mode は standalone か managed（段階 1 では standalone だけ）。
	Mode     string
	LogLevel slog.Level

	// GUIAddr は Web GUI の待ち受けアドレス（compose のネットワークの中。cloudflared からだけ受ける）。
	GUIAddr string
	// DataDir は SQLite と鍵のファイルを置くディレクトリ。
	DataDir string
	// TenantsDir はテナントの radsecproxy の設定を置くディレクトリ。agent がテナントのコンテナにマウントするホストのパスと
	// 同じパスで、radsec-edge のコンテナにもマウントする（設計概要 §10.2）。
	TenantsDir string
	// AgentSocket は agent の unix ソケット。
	AgentSocket string

	// URNPrefix は AP の証明書の SAN の URI の接頭辞（urn:<接頭辞>:nas:...）。DNSDomain はスロットの名前のドメイン。
	// どちらも CA（CA_URN_PREFIX、CA_DNS_DOMAIN）と同じ値にそろえる。
	URNPrefix string
	DNSDomain string

	// StampVendorID と StampVendorType はテナントの刻印の VSA（設計概要 §24.2）。上流の設定と食い違うとすべて拒否になるので、起動のときにログに出す。
	StampVendorID, StampVendorType int
	// Upstream は新しいテナントの上流の既定と、エッジで 1 つの共有シークレット（設計概要 §12.3）。
	Upstream Upstream

	// CRLBaseURL は CA の CRL の配布の口（例 http://10.0.0.1:8449）。空なら、テナントごとの取得先がなければ取りに行かない。
	CRLBaseURL string
	// CRLInterval は CRL を取りに行く間隔、CRLWarn は nextUpdate までの残りがこれを切ったら警告する値（設計概要 §9.5）。
	CRLInterval time.Duration
	CRLWarn     time.Duration
	// ReconcileInterval は整合ループの間隔（設計概要 §11.5）。
	ReconcileInterval time.Duration
	// ProbeTimeout はヘルスチェックの 1 回の上限、ApplyTimeout は反映の 1 回の上限。
	ProbeTimeout time.Duration
	ApplyTimeout time.Duration

	// AccessTeamDomain と AccessAUDs は Cloudflare Access の設定（設計概要 §13.1）。
	AccessTeamDomain string
	AccessAUDs       []string
	// DevUserEmail は開発用の設定。JWT を検証せず、このメールアドレスの利用者として動かす（ループバックで待ち受けるときだけ）。
	DevUserEmail string
}

// Upstream は上流の RADIUS サーバー。
type Upstream struct {
	// Auth と Acct は既定の認証と課金の宛先（IP アドレスとポート。空なら、テナントを作るときに入れる）。
	Auth, Acct netip.AddrPort
	// Secret はエッジで 1 つの共有シークレット。
	Secret string
}

// DevMode は開発用の設定で動くか。
func (c Config) DevMode() bool { return c.DevUserEmail != "" }

// Load は環境変数から設定を読む。誤りはまとめて返す。
func Load() (Config, error) {
	c := Config{
		Mode:        cmp.Or(os.Getenv("EDGE_MODE"), ModeStandalone),
		GUIAddr:     cmp.Or(os.Getenv("EDGE_GUI_ADDR"), ":8447"),
		DataDir:     cmp.Or(os.Getenv("EDGE_DATA_DIR"), "/data"),
		TenantsDir:  cmp.Or(os.Getenv("EDGE_TENANTS_DIR"), "/var/lib/radsec-edge/tenants"),
		AgentSocket: cmp.Or(os.Getenv("EDGE_AGENT_SOCKET"), "/run/radsec-edge-agent/agent.sock"),
		URNPrefix:   os.Getenv("EDGE_URN_PREFIX"),
		DNSDomain:   strings.ToLower(os.Getenv("EDGE_DNS_DOMAIN")),
		CRLBaseURL:  strings.TrimSuffix(os.Getenv("EDGE_CRL_BASE_URL"), "/"),
	}
	var errs []error
	if v := os.Getenv("EDGE_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("EDGE_LOG_LEVEL: %w", err))
		}
	}
	switch c.Mode {
	case ModeStandalone:
	case ModeManaged:
		errs = append(errs, errors.New("EDGE_MODE: managed is not implemented yet (use standalone)"))
	default:
		errs = append(errs, errors.New("EDGE_MODE: must be standalone or managed"))
	}
	if _, _, err := net.SplitHostPort(c.GUIAddr); err != nil {
		errs = append(errs, fmt.Errorf("EDGE_GUI_ADDR: %w", err))
	}
	for name, p := range map[string]string{"EDGE_DATA_DIR": c.DataDir, "EDGE_TENANTS_DIR": c.TenantsDir, "EDGE_AGENT_SOCKET": c.AgentSocket} {
		if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s: must be an absolute path", name))
		}
	}
	if err := names.CheckURNPrefix(c.URNPrefix); err != nil {
		errs = append(errs, fmt.Errorf("EDGE_URN_PREFIX: %w", err))
	}
	if err := names.CheckDomain(c.DNSDomain); err != nil {
		errs = append(errs, fmt.Errorf("EDGE_DNS_DOMAIN: %w", err))
	}
	errs = append(errs, c.loadUpstream()...)
	errs = append(errs, c.loadStamp()...)
	if c.CRLBaseURL != "" {
		if u, err := url.Parse(c.CRLBaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" {
			errs = append(errs, errors.New("EDGE_CRL_BASE_URL: must be an http(s) URL such as http://10.0.0.1:8449"))
		}
	}
	durations := []struct {
		env      string
		dst      *time.Duration
		def      time.Duration
		min, max time.Duration
	}{
		{"EDGE_CRL_INTERVAL", &c.CRLInterval, 5 * time.Minute, 10 * time.Second, 24 * time.Hour},
		{"EDGE_CRL_WARN", &c.CRLWarn, 72 * time.Hour, time.Hour, 30 * 24 * time.Hour},
		{"EDGE_RECONCILE_INTERVAL", &c.ReconcileInterval, time.Minute, 5 * time.Second, time.Hour},
		{"EDGE_PROBE_TIMEOUT", &c.ProbeTimeout, 10 * time.Second, time.Second, time.Minute},
		{"EDGE_APPLY_TIMEOUT", &c.ApplyTimeout, 2 * time.Minute, 10 * time.Second, 10 * time.Minute},
	}
	for _, d := range durations {
		*d.dst = d.def
		v := os.Getenv(d.env)
		if v == "" {
			continue
		}
		x, err := time.ParseDuration(v)
		if err != nil || x < d.min || x > d.max {
			errs = append(errs, fmt.Errorf("%s: must be a duration between %s and %s", d.env, d.min, d.max))
			continue
		}
		*d.dst = x
	}
	errs = append(errs, c.loadAuth()...)
	return c, errors.Join(errs...)
}

// loadStamp はテナントの刻印の VSA を読む。
func (c *Config) loadStamp() []error {
	var errs []error
	for _, d := range []struct {
		env      string
		dst      *int
		def, max int
	}{
		{"EDGE_STAMP_VENDOR_ID", &c.StampVendorID, defaultStampVendorID, 16777215},
		{"EDGE_STAMP_VENDOR_TYPE", &c.StampVendorType, defaultStampVendorType, 255},
	} {
		*d.dst = d.def
		if v := os.Getenv(d.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > d.max {
				errs = append(errs, fmt.Errorf("%s: must be an integer between 1 and %d", d.env, d.max))
				continue
			}
			*d.dst = n
		}
	}
	return errs
}

func (c *Config) loadUpstream() []error {
	var errs []error
	for _, u := range []struct {
		env string
		dst *netip.AddrPort
	}{{"EDGE_UPSTREAM_AUTH", &c.Upstream.Auth}, {"EDGE_UPSTREAM_ACCT", &c.Upstream.Acct}} {
		v := os.Getenv(u.env)
		if v == "" {
			continue
		}
		ap, err := ParseUpstream(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u.env, err))
			continue
		}
		*u.dst = ap
	}
	c.Upstream.Secret = os.Getenv("EDGE_UPSTREAM_SECRET")
	if !rsconf.ValidSecret(c.Upstream.Secret) {
		errs = append(errs, errors.New("EDGE_UPSTREAM_SECRET: must be 8 to 128 characters of letters, digits and ._~+/=@-"))
	}
	return errs
}

// ParseUpstream は上流の宛先（IP アドレス:ポート）を読む。ホスト名は受け付けない（radsecproxy は起動のときに
// 名前を引けないと終了するため。設計概要 §10.3）。
func ParseUpstream(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
	if err != nil || ap.Port() == 0 || !ap.Addr().IsValid() || ap.Addr().Zone() != "" || ap.Addr().IsUnspecified() {
		return netip.AddrPort{}, errors.New("must be an IP address and port such as 10.0.0.10:1812 (host names are not allowed)")
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// hostnamePattern はチームのドメインの形式。
var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// emailPattern は開発用の利用者のメールアドレスの形式（監査ログの操作者に使う）。
var emailPattern = regexp.MustCompile(`^[a-z0-9._-]+@[a-z0-9._-]+$`)

// loadAuth は利用者の識別の設定を読む。Access と開発用の設定のどちらか一方だけを受け付ける。
func (c *Config) loadAuth() []error {
	var errs []error
	c.AccessTeamDomain = strings.ToLower(strings.TrimSpace(os.Getenv("EDGE_ACCESS_TEAM_DOMAIN")))
	for v := range strings.SplitSeq(os.Getenv("EDGE_ACCESS_AUD"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			c.AccessAUDs = append(c.AccessAUDs, v)
		}
	}
	c.DevUserEmail = strings.ToLower(strings.TrimSpace(os.Getenv("EDGE_DEV_USER_EMAIL")))
	access := c.AccessTeamDomain != "" || len(c.AccessAUDs) > 0
	switch {
	case access && c.DevUserEmail != "":
		errs = append(errs, errors.New("EDGE_DEV_USER_EMAIL cannot be used with the Cloudflare Access settings (EDGE_ACCESS_*)"))
	case access:
		if c.AccessTeamDomain == "" || len(c.AccessAUDs) == 0 {
			errs = append(errs, errors.New("both EDGE_ACCESS_TEAM_DOMAIN and EDGE_ACCESS_AUD are required"))
		} else if !hostnamePattern.MatchString(c.AccessTeamDomain) {
			errs = append(errs, errors.New("EDGE_ACCESS_TEAM_DOMAIN: must be a host name such as example.cloudflareaccess.com"))
		}
	case c.DevUserEmail != "":
		if !emailPattern.MatchString(c.DevUserEmail) || len(c.DevUserEmail) > 64 {
			errs = append(errs, errors.New("EDGE_DEV_USER_EMAIL: must be an email address of up to 64 characters using only letters, digits and ._-"))
		}
		// 開発用の設定は、他のホストから届かない待ち受けでだけ使う。
		if host, _, err := net.SplitHostPort(c.GUIAddr); err == nil && !isLoopback(host) {
			errs = append(errs, fmt.Errorf("EDGE_DEV_USER_EMAIL can be used only when EDGE_GUI_ADDR is a loopback address (got %q)", c.GUIAddr))
		}
	default:
		errs = append(errs, errors.New("set EDGE_ACCESS_TEAM_DOMAIN and EDGE_ACCESS_AUD (Cloudflare Access), "+
			"or EDGE_DEV_USER_EMAIL for development"))
	}
	return errs
}

// isLoopback は、待ち受けのホストがループバックか（空や 0.0.0.0 はすべてのアドレスなので違う）。
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Agent は radsec-edge-agent の設定。
type Agent struct {
	LogLevel slog.Level
	// Socket は待ち受ける unix ソケット（radsec-edge と共有するボリュームの中）。
	Socket string
	// SocketGID はソケットのグループ（radsec-edge のグループ。設計概要 §10.2）。
	SocketGID int
	// DockerSocket は Docker Engine の unix ソケット。
	DockerSocket string
	// TenantsDir はテナントの設定を置くホストのパス（テナントのコンテナにマウントする）。
	TenantsDir string
	// Network はテナントのコンテナを置く Docker のネットワーク。
	Network string
	// PublishAddr はテナントのポートを公開するホストのアドレス（空ならすべてのアドレス。設計概要 §10.2）。
	PublishAddr string
}

// LoadAgent は環境変数から agent の設定を読む。
func LoadAgent() (Agent, error) {
	a := Agent{
		Socket:       cmp.Or(os.Getenv("EDGE_AGENT_SOCKET"), "/run/radsec-edge-agent/agent.sock"),
		DockerSocket: cmp.Or(os.Getenv("EDGE_AGENT_DOCKER_SOCKET"), "/var/run/docker.sock"),
		TenantsDir:   cmp.Or(os.Getenv("EDGE_TENANTS_DIR"), "/var/lib/radsec-edge/tenants"),
		Network:      cmp.Or(os.Getenv("EDGE_AGENT_NETWORK"), "radsec-edge-tenants"),
		SocketGID:    10083,
	}
	var errs []error
	if v := os.Getenv("EDGE_LOG_LEVEL"); v != "" {
		if err := a.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("EDGE_LOG_LEVEL: %w", err))
		}
	}
	if v := os.Getenv("EDGE_AGENT_SOCKET_GID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1<<31-1 {
			errs = append(errs, errors.New("EDGE_AGENT_SOCKET_GID: must be a group ID"))
		}
		a.SocketGID = n
	}
	for name, p := range map[string]string{"EDGE_AGENT_SOCKET": a.Socket, "EDGE_AGENT_DOCKER_SOCKET": a.DockerSocket, "EDGE_TENANTS_DIR": a.TenantsDir} {
		if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("%s: must be an absolute path", name))
		}
	}
	if v := strings.TrimSpace(os.Getenv("EDGE_AGENT_PUBLISH_ADDR")); v != "" {
		ip, err := netip.ParseAddr(v)
		if err != nil || ip.Zone() != "" {
			errs = append(errs, errors.New("EDGE_AGENT_PUBLISH_ADDR: must be an IP address (or empty for all addresses)"))
		} else {
			a.PublishAddr = ip.String()
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`).MatchString(a.Network) {
		errs = append(errs, errors.New("EDGE_AGENT_NETWORK: must be a Docker network name"))
	}
	return a, errors.Join(errs...)
}
