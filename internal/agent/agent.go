// Package agent は radsec-edge-agent（Docker Engine を操作する唯一の部品。設計概要 §10）の API と、
// radsec-edge から呼ぶクライアントを提供する。
//
// agent は unix ソケットで決まった操作だけを受け付け、テナントの radsecproxy のコンテナを固定のひな形（§10.2）から作る。
// 要求からは、イメージ・マウント・権限を指定させない（radsec-edge が乗っ取られても、勝手なコンテナは作れない）。
// 要求で受け取るのは、テナントの ID と slug（§8.1 の規則）、ポート（20830〜20999）、版の名前（16 進 16 桁）、ログの行数だけ。
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"
)

// Image は radsecproxy のイメージ（images/radsecproxy で作る。設計概要 §4）。
const Image = "radsec-edge/radsecproxy:1.11.2-1-deb13u1"

// コンテナのラベル（設計概要 §10.2）。ラベルのないコンテナには触れない。
const (
	LabelTenant   = "radsec-edge.tenant"
	LabelSlug     = "radsec-edge.slug"
	LabelPort     = "radsec-edge.port"
	LabelSpec     = "radsec-edge.spec"
	LabelValidate = "radsec-edge.validate"
)

// コンテナのひな形の値（設計概要 §10.2）。
const (
	// User は radsecproxy の UID と GID。
	User = "10083:10083"
	// ContainerPort は radsecproxy が待ち受けるコンテナの中のポート。
	ContainerPort = "2083/tcp"
	// MountTarget はテナントのディレクトリをマウントする場所。
	MountTarget = "/conf"
	// confPath は radsecproxy の設定（MountTarget/current/radsecproxy.conf）。
	confPath = "/conf/current/radsecproxy.conf"
	// ポートの範囲。
	PortMin = 20830
	PortMax = 20999
	// stopTimeout は停止の猶予（init を使うので、radsecproxy は SIGTERM ですぐ止まる。§18.1 の V6）。
	stopTimeout = 10 * time.Second
	// validateTimeout は構文検査の上限。
	validateTimeout = 30 * time.Second
)

// ContainerName はテナントのコンテナの名前。
func ContainerName(slug string) string { return "radsecproxy-" + slug }

// Container はテナントのコンテナの状態。
type Container struct {
	TenantID     string    `json:"tenant_id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	ID           string    `json:"id"`
	State        string    `json:"state"`
	Running      bool      `json:"running,omitzero"`
	Restarting   bool      `json:"restarting,omitzero"`
	RestartCount int       `json:"restart_count,omitzero"`
	ExitCode     int       `json:"exit_code,omitzero"`
	StartedAt    time.Time `json:"started_at,omitzero"`
	Port         int       `json:"port,omitzero"`
	// SpecCurrent は、今のひな形で作ったコンテナか（違えば次の Ensure で作り直す）。
	SpecCurrent bool `json:"spec_current,omitzero"`
}

// Status は agent と Docker の状態。
type Status struct {
	Version        string      `json:"version"`
	DockerOK       bool        `json:"docker_ok,omitzero"`
	DockerError    string      `json:"docker_error,omitempty"`
	Image          string      `json:"image"`
	ImagePresent   bool        `json:"image_present,omitzero"`
	Network        string      `json:"network"`
	NetworkPresent bool        `json:"network_present,omitzero"`
	Containers     []Container `json:"containers"`
}

// Container は tenantID のコンテナを返す（なければ false）。
func (s Status) Container(tenantID string) (Container, bool) {
	for _, c := range s.Containers {
		if c.TenantID == tenantID {
			return c, true
		}
	}
	return Container{}, false
}

// EnsureRequest は EnsureTenant の要求。
type EnsureRequest struct {
	Slug string `json:"slug"`
	Port int    `json:"port"`
}

// Ensure の結果（EnsureResult.Action）。
const (
	EnsureNone      = "none"      // 動いていた
	EnsureStarted   = "started"   // 止まっていたので起動した
	EnsureCreated   = "created"   // なかったので作って起動した
	EnsureRecreated = "recreated" // ひな形やポートが違ったので作り直して起動した
)

// EnsureResult は EnsureTenant の結果。
type EnsureResult struct {
	Action string `json:"action"`
}

// ValidateRequest は Validate の要求（テナントの slug と版の名前）。
type ValidateRequest struct {
	Slug string `json:"slug"`
	Gen  string `json:"gen"`
}

// ValidateResult は Validate の結果（radsecproxy -p の終了コードが 0 なら OK）。
type ValidateResult struct {
	OK     bool   `json:"ok,omitzero"`
	Output string `json:"output"`
}

// SignalRequest は Signal の要求（HUP だけ）。
type SignalRequest struct {
	Signal string `json:"signal"`
}

// LogsResult は Logs の結果。
type LogsResult struct {
	Logs string `json:"logs"`
}

// errorBody はエラーの応答。
type errorBody struct {
	Error string `json:"error"`
}

// ErrNotFound はテナントのコンテナがないことを表す。
var ErrNotFound = errors.New("agent: container not found")

// Error は agent が返したエラー。
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("agent: %d %s", e.Status, e.Message) }

func (e *Error) Is(target error) bool { return target == ErrNotFound && e.Status == 404 }

// spec はテナントのコンテナのひな形（Engine API の ContainerCreate の本文）。
type spec struct {
	Image        string              `json:"Image"`
	User         string              `json:"User"`
	Cmd          []string            `json:"Cmd"`
	Labels       map[string]string   `json:"Labels"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   hostConfig          `json:"HostConfig"`
}

type hostConfig struct {
	Mounts         []mount                  `json:"Mounts"`
	PortBindings   map[string][]portBinding `json:"PortBindings,omitempty"`
	RestartPolicy  restartPolicy            `json:"RestartPolicy"`
	Init           bool                     `json:"Init"`
	ReadonlyRootfs bool                     `json:"ReadonlyRootfs"`
	CapDrop        []string                 `json:"CapDrop"`
	SecurityOpt    []string                 `json:"SecurityOpt"`
	Privileged     bool                     `json:"Privileged"`
	LogConfig      logConfig                `json:"LogConfig"`
	NetworkMode    string                   `json:"NetworkMode"`
}

type mount struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type restartPolicy struct {
	Name string `json:"Name"`
}

type logConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// tenantSpec はテナントのコンテナのひな形を作る（設計概要 §10.2）。値はすべて検証済みのもの。
func tenantSpec(tenantsDir, network, tenantID, slug string, port int) spec {
	s := baseSpec(network)
	s.Cmd = []string{"radsecproxy", "-f", "-c", confPath}
	s.Labels = map[string]string{LabelTenant: tenantID, LabelSlug: slug, LabelPort: strconv.Itoa(port)}
	s.ExposedPorts = map[string]struct{}{ContainerPort: {}}
	s.HostConfig.Mounts = []mount{{Type: "bind", Source: path.Join(tenantsDir, slug), Target: MountTarget, ReadOnly: true}}
	s.HostConfig.PortBindings = map[string][]portBinding{ContainerPort: {{HostIP: "", HostPort: strconv.Itoa(port)}}}
	s.HostConfig.RestartPolicy = restartPolicy{Name: "unless-stopped"}
	s.Labels[LabelSpec] = specHash(s)
	return s
}

// validateSpec は構文検査の捨てるコンテナのひな形。検査する版のディレクトリを /conf/current にマウントする（§10.2）。
// server ブロックの上流に届くよう、テナントと同じネットワークで動かす（§10.1）。
func validateSpec(tenantsDir, network, slug, gen string) spec {
	s := baseSpec(network)
	s.Cmd = []string{"radsecproxy", "-p", "-c", confPath}
	s.Labels = map[string]string{LabelValidate: slug}
	s.HostConfig.Mounts = []mount{{Type: "bind", Source: path.Join(tenantsDir, slug, "gen", gen), Target: MountTarget + "/current", ReadOnly: true}}
	s.HostConfig.RestartPolicy = restartPolicy{Name: "no"}
	return s
}

// baseSpec は、テナントのコンテナと捨てるコンテナに共通のひな形（nonroot、読み取り専用、権限なし、init、ログの回転）。
func baseSpec(network string) spec {
	return spec{
		Image: Image,
		User:  User,
		HostConfig: hostConfig{
			Init:           true,
			ReadonlyRootfs: true,
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			Privileged:     false,
			LogConfig:      logConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "5"}},
			NetworkMode:    network,
		},
	}
}

// specHash はひな形のハッシュ（ラベル LabelSpec に入れ、ひな形やポートが変わったら作り直す）。
func specHash(s spec) string {
	s.Labels = map[string]string{LabelTenant: s.Labels[LabelTenant], LabelSlug: s.Labels[LabelSlug], LabelPort: s.Labels[LabelPort]}
	h := sha256.New()
	fmt.Fprintf(h, "%v|%v|%v|%v|%+v|%+v|%+v", s.Image, s.User, s.Cmd, s.Labels, s.HostConfig.Mounts, s.HostConfig.PortBindings, s.HostConfig)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
