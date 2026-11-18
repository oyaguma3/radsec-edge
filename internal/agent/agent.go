// Package agent は radsec-edge-agent（Docker Engine を操作する唯一の部品。設計概要 §10）の API と、
// radsec-edge から呼ぶクライアントを提供する。
//
// agent は unix ソケットで決まった操作だけを受け付け、テナントの radsecproxy のコンテナを固定のひな形（§10.2）から作る。
// 要求からは、イメージ・マウント・権限を指定させない（radsec-edge が乗っ取られても、勝手なコンテナは作れない）。
// 要求で受け取るのは、テナントの ID と slug（§8.1 の規則）、ポート（20000〜21999）、版の名前（16 進 16 桁）、ログの行数、
// ひな形の版（コードが知っている番号だけ）と radsecproxy のイメージの ID（ImageRepo のタグの付いたイメージだけ。§24.14 の U6-5）だけ。
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Image は radsecproxy のイメージ（images/radsecproxy で作る。設計概要 §4）。新しく作るテナントのコンテナと、
// 新しい形へ反映し直すコンテナは、このタグが今指しているイメージ（の ID）で作る（§24.14 の U6-1）。
const Image = ImageRepo + ":1.11.5-pc2"

// ImageRepo は radsecproxy のイメージのリポジトリの名前。agent がコンテナに使うのは、このリポジトリのタグの付いたイメージだけ。
// テナントのコンテナが使っているイメージにタグがなくなったら（同じタグで新しいイメージを読み込んだとき）、
// KeepTagPrefix のタグを付けて残し、前の形に戻せるようにする（§24.14 の U6-5）。
const ImageRepo = "radsec-edge/radsecproxy"

// KeepTagPrefix は、前のイメージを残すために agent が付けるタグの頭（keep-<イメージの ID の 12 桁>）。
const KeepTagPrefix = "keep-"

// LatestTemplate はコードの最新のひな形の版。Templates はこのコードが作れるひな形の版（今と 1 つ前まで。§24.14 の U6-5）。
// ひな形（起動のしかた・環境変数・マウントなど）や、radsecproxy の版でしか読めない設定の書き方を変えるときは、版を 1 つ上げ、
// 前の版の作り方を 1 つだけ残す。
//   - 版 1: 段階 6-0 の形（radsecproxy 1.11.4-pc1 で動く）。
//   - 版 2: コンテナの作りは版 1 と同じで、テナントの radsecproxy.conf の client ブロックに IdleTimeout 0 を書く（rsconf の Input.Template）。
//     IdleTimeout は client-idletimeout.patch のあるイメージ（1.11.5-pc2 から）でしか読めないので、版を分けて前の形（版 1 と古いイメージ）に
//     戻せるようにする（§24.15）。
const LatestTemplate = 2

// Templates はこのコードが作れるひな形の版。
var Templates = []int{1, 2}

// KnownTemplate は v がこのコードで作れるひな形の版か。
func KnownTemplate(v int) bool { return slices.Contains(Templates, v) }

// Ref はテナントのコンテナのひな形（ひな形の版と radsecproxy のイメージの ID）。零値は「今の形」（最新の版と今のタグのイメージ）。
type Ref struct {
	Template int    `json:"template,omitzero"`
	Image    string `json:"image,omitempty"`
}

// IsZero は零値か。
func (r Ref) IsZero() bool { return r.Template == 0 && r.Image == "" }

// ShortImage はイメージの ID の短い形（sha256: を除いた 12 桁）。
func ShortImage(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	return id[:min(12, len(id))]
}

// コンテナのラベル（設計概要 §10.2）。ラベルのないコンテナには触れない。
const (
	LabelTenant   = "radsec-edge.tenant"
	LabelSlug     = "radsec-edge.slug"
	LabelPort     = "radsec-edge.port"
	LabelSpec     = "radsec-edge.spec"
	LabelTemplate = "radsec-edge.template"
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
	// mallocArenaMax は radsecproxy の glibc の malloc の領域（arena）の数の上限（§24.13 の T5-21）。
	// radsecproxy は AP の接続ごとにスレッドを作り、malloc はスレッドごとに領域を足して返さないので、既定のままだと
	// 同時のスレッドの数に応じて 1 個あたりのメモリーが増える（上限は 8 × コア数）。2 に絞って、AP の数によらず上限を決める。
	mallocArenaMax = "MALLOC_ARENA_MAX=2"
	// confPath は radsecproxy の設定（MountTarget/current/radsecproxy.conf）。
	confPath = "/conf/current/radsecproxy.conf"
	// ポートの範囲。
	PortMin = 20000
	PortMax = 21999
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
	// Template はコンテナのひな形の版（ラベルとひな形のハッシュから分かったもの。分からなければ 0）、ImageID は使っているイメージの ID。
	// 段階 6 より前の作りで作ったコンテナは、そのときのハッシュの作り方で照らして版 1 とみなす（§24.14 の U6-5）。
	Template int    `json:"template,omitzero"`
	ImageID  string `json:"image_id,omitempty"`
}

// Ref はコンテナのひな形を返す。
func (c Container) Ref() Ref { return Ref{Template: c.Template, Image: c.ImageID} }

// ImageInfo はホストにある radsecproxy のイメージ。
type ImageInfo struct {
	ID      string    `json:"id"`
	Tags    []string  `json:"tags"`
	Created time.Time `json:"created,omitzero"`
	// InUse はこのイメージを使っているテナントのコンテナの数。
	InUse int `json:"in_use,omitzero"`
}

// Status は agent と Docker の状態。
type Status struct {
	Version     string `json:"version"`
	DockerOK    bool   `json:"docker_ok,omitzero"`
	DockerError string `json:"docker_error,omitempty"`
	Image       string `json:"image"`
	// ImageID は Image のタグが今指しているイメージの ID（なければ空）。LatestTemplate はコードの最新のひな形の版、Templates は作れる版。
	ImageID        string `json:"image_id,omitempty"`
	LatestTemplate int    `json:"latest_template"`
	Templates      []int  `json:"templates"`
	// Images はホストにある radsecproxy のイメージ（ImageRepo のタグの付いたもの）。
	Images []ImageInfo `json:"images,omitempty"`
	// NetworkSubnets はテナントのネットワークのサブネット（ヘルスチェックの送信元。送信元の範囲を持つテナントで使う。§24.3）。
	NetworkSubnets []string    `json:"network_subnets,omitempty"`
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

// Latest は今の形（最新のひな形の版と、今のタグのイメージ）を返す。
func (s Status) Latest() Ref { return Ref{Template: s.LatestTemplate, Image: s.ImageID} }

// EnsureRequest は EnsureTenant の要求。Ref が零値なら今の形で作る。
type EnsureRequest struct {
	Slug string `json:"slug"`
	Port int    `json:"port"`
	Ref  `json:",inline"`
}

// Ensure の結果（EnsureResult.Action）。
const (
	EnsureNone      = "none"      // 動いていた
	EnsureStarted   = "started"   // 止まっていたので起動した
	EnsureCreated   = "created"   // なかったので作って起動した
	EnsureRecreated = "recreated" // ひな形やポートが違ったので作り直して起動した
)

// EnsureResult は EnsureTenant の結果（行ったことと、使ったひな形）。
type EnsureResult struct {
	Action string `json:"action"`
	Ref    Ref    `json:"ref"`
}

// ValidateRequest は Validate の要求（テナントの slug と版の名前、検査に使うイメージの ID。空なら今のタグのイメージ）。
type ValidateRequest struct {
	Slug  string `json:"slug"`
	Gen   string `json:"gen"`
	Image string `json:"image,omitempty"`
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

// LogsResult は Logs の結果。Timestamps を指定したときは、各行の先頭に Docker が受け取った時刻（RFC 3339 のナノ秒）が付く。
type LogsResult struct {
	Logs string `json:"logs"`
}

// errorBody はエラーの応答。
type errorBody struct {
	Error string `json:"error"`
}

// ErrNotFound はテナントのコンテナがないことを表す。
var ErrNotFound = errors.New("agent: container not found")

// ErrImageNotAllowed は、要求のイメージがない、または ImageRepo のタグの付いたイメージでないことを表す（409）。
// ErrUnknownTemplate は、要求のひな形の版をこのコードが作れないことを表す（409）。
var (
	ErrImageNotAllowed = errors.New("agent: image is missing or not a radsecproxy image")
	ErrUnknownTemplate = errors.New("agent: unknown template version")
)

// Error は agent が返したエラー。
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("agent: %d %s", e.Status, e.Message) }

func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == 404
	case ErrImageNotAllowed:
		return e.Status == 409 && strings.HasPrefix(e.Message, ErrImageNotAllowed.Error())
	case ErrUnknownTemplate:
		return e.Status == 409 && strings.HasPrefix(e.Message, ErrUnknownTemplate.Error())
	}
	return false
}

// spec はテナントのコンテナのひな形（Engine API の ContainerCreate の本文）。
type spec struct {
	Image        string              `json:"Image"`
	User         string              `json:"User"`
	Cmd          []string            `json:"Cmd"`
	Env          []string            `json:"Env,omitempty"`
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

// fluentdLog は、テナントのコンテナのログを Fluent Bit に送る設定（§24.11 の EA14。aka-mvpset の verify/edge-logs）。待ち行列はコンテナごとに確保され、
// 既定の値（1,048,576 件）だと 150 テナントで dockerd が約 480 MiB 増えるので絞る。docker logs は dual logging のキャッシュで読める（last-seen が使う）。
func fluentdLog(address, tenantID string) logConfig {
	return logConfig{Type: "fluentd", Config: map[string]string{
		"fluentd-address": address, "fluentd-async": "true", "fluentd-buffer-limit": "8192", "tag": "tenant." + tenantID,
		"cache-max-size": "10m", "cache-max-file": "2",
	}}
}

// tenantSpec はテナントのコンテナのひな形を作る（設計概要 §10.2）。値はすべて検証済みのもの。ref.Image はイメージの ID で、
// ref.Template の版の作り方で作る（作れない版なら ErrUnknownTemplate）。
// publishAddr はテナントのポートを公開するホストのアドレス（空ならすべてのアドレス。§10.2）。fluentd は Fluent Bit のアドレス（空なら json-file のまま）。
func tenantSpec(tenantsDir, network, publishAddr, fluentd, tenantID, slug string, port int, ref Ref) (spec, error) {
	switch ref.Template {
	case 1, 2:
		// 版 2 のコンテナの作りは版 1 と同じ（違いはテナントの設定の書き方だけ）。版のラベルはハッシュに入るので、版を替えると作り直す。
		s := tenantSpecV1(tenantsDir, network, publishAddr, fluentd, tenantID, slug, port)
		s.Image = ref.Image
		s.Labels[LabelTemplate] = strconv.Itoa(ref.Template)
		s.Labels[LabelSpec] = specHash(s)
		return s, nil
	}
	return spec{}, fmt.Errorf("%w: %d", ErrUnknownTemplate, ref.Template)
}

// legacyImage と legacySpecHash は、段階 6 より前の作り（イメージをタグで指定し、ひな形の版のラベルがない）のハッシュ。
// その作りで作ったコンテナを版 1 とみなすのに使う（作り直さずに記録するため。§24.14 の U6-5）。版 1 を作れなくなる版では消す。
const legacyImage = "radsec-edge/radsecproxy:1.11.4-pc1"

func legacySpecHash(tenantsDir, network, publishAddr, fluentd, tenantID, slug string, port int) string {
	s := tenantSpecV1(tenantsDir, network, publishAddr, fluentd, tenantID, slug, port)
	s.Image = legacyImage
	s.Labels = map[string]string{LabelTenant: s.Labels[LabelTenant], LabelSlug: s.Labels[LabelSlug], LabelPort: s.Labels[LabelPort]}
	h := sha256.New()
	fmt.Fprintf(h, "%v|%v|%v|%v|%v|%+v|%+v|%+v", s.Image, s.User, s.Cmd, s.Env, s.Labels, s.HostConfig.Mounts, s.HostConfig.PortBindings, s.HostConfig)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// tenantSpecV1 はひな形の版 1（イメージ、ひな形のラベル、ハッシュは呼び出し側で入れる）。
func tenantSpecV1(tenantsDir, network, publishAddr, fluentd, tenantID, slug string, port int) spec {
	s := baseSpec(network)
	if fluentd != "" {
		s.HostConfig.LogConfig = fluentdLog(fluentd, tenantID)
	}
	s.Cmd = []string{"radsecproxy", "-f", "-c", confPath}
	s.Env = []string{mallocArenaMax}
	s.Labels = map[string]string{LabelTenant: tenantID, LabelSlug: slug, LabelPort: strconv.Itoa(port)}
	s.ExposedPorts = map[string]struct{}{ContainerPort: {}}
	s.HostConfig.Mounts = []mount{{Type: "bind", Source: path.Join(tenantsDir, slug), Target: MountTarget, ReadOnly: true}}
	s.HostConfig.PortBindings = map[string][]portBinding{ContainerPort: {{HostIP: publishAddr, HostPort: strconv.Itoa(port)}}}
	s.HostConfig.RestartPolicy = restartPolicy{Name: "unless-stopped"}
	return s
}

// validateSpec は構文検査の捨てるコンテナのひな形。検査する版のディレクトリを /conf/current にマウントする（§10.2）。
// server ブロックの上流に届くよう、テナントと同じネットワークで動かす（§10.1）。image は検査に使うイメージ（テナントが動かすもの）。
func validateSpec(tenantsDir, network, slug, gen, image string) spec {
	s := baseSpec(network)
	s.Image = image
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

// specHash はひな形のハッシュ（ラベル LabelSpec に入れ、ひな形やポートが違うコンテナは作り直す）。イメージの ID、環境変数、ひな形の版も含める。
func specHash(s spec) string {
	s.Labels = map[string]string{LabelTenant: s.Labels[LabelTenant], LabelSlug: s.Labels[LabelSlug], LabelPort: s.Labels[LabelPort], LabelTemplate: s.Labels[LabelTemplate]}
	h := sha256.New()
	fmt.Fprintf(h, "%v|%v|%v|%v|%v|%+v|%+v|%+v", s.Image, s.User, s.Cmd, s.Env, s.Labels, s.HostConfig.Mounts, s.HostConfig.PortBindings, s.HostConfig)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
