// Package edgetest は、edge と画面の試験で使う偽物の agent とヘルスチェックを提供する。
package edgetest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
)

// FakeAgent は agent の代わり（コンテナの状態を覚え、呼び出しを記録する）。
type FakeAgent struct {
	mu         sync.Mutex
	Containers map[string]*agent.Container
	calls      []string
	// LogsText はテナントごとに LogsSince が返すログ、Since は LogsSince に渡された時刻の記録。
	LogsText map[string]string
	Since    []time.Time
	// NetworkSubnets はテナントのネットワークのサブネット。
	NetworkSubnets []string
	// ValidateOK は Validate の結果、FailEnsure は Ensure の誤り。
	ValidateOK bool
	FailEnsure error
	// ValidateWait は Validate の前に呼ぶ（nil でなければ）。誤りを返すと Validate はその誤りを返す（止めるときの取り消しの試験）。
	ValidateWait func(ctx context.Context) error
	// ImageID は今のタグのイメージの ID、Images はホストにある radsecproxy のイメージの ID（ImageID は含めなくてよい）。
	// Validated は Validate に渡されたイメージの記録。
	ImageID   string
	Images    []string
	Validated []string
}

// テスト用のイメージの ID。
const (
	ImageA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ImageB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// NewFakeAgent は偽物の agent を作る。
func NewFakeAgent() *FakeAgent {
	return &FakeAgent{Containers: map[string]*agent.Container{}, LogsText: map[string]string{}, ValidateOK: true, ImageID: ImageA}
}

func (f *FakeAgent) call(s string) {
	f.calls = append(f.calls, s)
}

// TakeCalls は記録した呼び出しを返して空にする。
func (f *FakeAgent) TakeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func (f *FakeAgent) Status(context.Context) (agent.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := agent.Status{DockerOK: true, ImagePresent: f.ImageID != "", ImageID: f.ImageID, NetworkPresent: true, NetworkSubnets: f.NetworkSubnets,
		Image: agent.Image, LatestTemplate: agent.LatestTemplate, Templates: agent.Templates}
	for _, id := range f.images() {
		st.Images = append(st.Images, agent.ImageInfo{ID: id})
	}
	for _, c := range f.Containers {
		st.Containers = append(st.Containers, *c)
	}
	return st, nil
}

// images はホストにあるイメージの ID（今のタグのものと Images）。
func (f *FakeAgent) images() []string {
	out := slices.Clone(f.Images)
	if f.ImageID != "" && !slices.Contains(out, f.ImageID) {
		out = append(out, f.ImageID)
	}
	return out
}

// resolve は agent と同じく、零値を今の形にし、ないイメージと作れない版を断る。
func (f *FakeAgent) resolve(ref agent.Ref) (agent.Ref, error) {
	if ref.Template == 0 {
		ref.Template = agent.LatestTemplate
	}
	if ref.Image == "" {
		ref.Image = f.ImageID
	}
	if !agent.KnownTemplate(ref.Template) {
		return agent.Ref{}, &agent.Error{Status: 409, Message: agent.ErrUnknownTemplate.Error()}
	}
	if ref.Image == "" || !slices.Contains(f.images(), ref.Image) {
		return agent.Ref{}, &agent.Error{Status: 409, Message: agent.ErrImageNotAllowed.Error()}
	}
	return ref, nil
}

func (f *FakeAgent) Ensure(_ context.Context, id, slug string, port int, ref agent.Ref) (agent.EnsureResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ensure " + id)
	if f.FailEnsure != nil {
		return agent.EnsureResult{}, f.FailEnsure
	}
	ref, err := f.resolve(ref)
	if err != nil {
		return agent.EnsureResult{}, err
	}
	c, ok := f.Containers[id]
	switch {
	case !ok:
		f.Containers[id] = &agent.Container{TenantID: id, Slug: slug, Name: agent.ContainerName(slug), State: "running", Running: true, Port: port,
			Template: ref.Template, ImageID: ref.Image}
		return agent.EnsureResult{Action: agent.EnsureCreated, Ref: ref}, nil
	case c.Port != port || c.Ref() != ref:
		f.call("recreate " + id)
		c.Port, c.Running, c.State, c.Template, c.ImageID = port, true, "running", ref.Template, ref.Image
		return agent.EnsureResult{Action: agent.EnsureRecreated, Ref: ref}, nil
	case !c.Running:
		c.Running, c.State = true, "running"
		return agent.EnsureResult{Action: agent.EnsureStarted, Ref: ref}, nil
	}
	return agent.EnsureResult{Action: agent.EnsureNone, Ref: ref}, nil
}

func (f *FakeAgent) op(name, id string, fn func(c *agent.Container)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call(name + " " + id)
	c, ok := f.Containers[id]
	if !ok {
		return agent.ErrNotFound
	}
	if fn != nil {
		fn(c)
	}
	return nil
}

func (f *FakeAgent) Restart(_ context.Context, id string) error { return f.op("restart", id, nil) }
func (f *FakeAgent) SIGHUP(_ context.Context, id string) error  { return f.op("sighup", id, nil) }
func (f *FakeAgent) Stop(_ context.Context, id string) error {
	return f.op("stop", id, func(c *agent.Container) { c.Running, c.State = false, "exited" })
}
func (f *FakeAgent) Remove(_ context.Context, id string) error {
	err := f.op("remove", id, nil)
	f.mu.Lock()
	delete(f.Containers, id)
	f.mu.Unlock()
	return err
}
func (f *FakeAgent) Logs(context.Context, string, int) (string, error) { return "", nil }

// LogsSince は SetLogs で与えたログを返す（since は記録する）。
func (f *FakeAgent) LogsSince(_ context.Context, id string, since time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Since = append(f.Since, since)
	return f.LogsText[id], nil
}
func (f *FakeAgent) Validate(ctx context.Context, slug, gen, image string) (agent.ValidateResult, error) {
	f.mu.Lock()
	f.call("validate " + slug)
	f.Validated = append(f.Validated, image)
	wait := f.ValidateWait
	f.mu.Unlock()
	if wait != nil {
		if err := wait(ctx); err != nil {
			return agent.ValidateResult{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ValidateOK {
		return agent.ValidateResult{Output: "syntax error"}, nil
	}
	return agent.ValidateResult{OK: true}, nil
}

// FakeProbe はヘルスチェックの代わり。SetFail(true) の間は失敗する。
type FakeProbe struct {
	mu   sync.Mutex
	fail bool
	// Addrs はヘルスチェックの宛先の記録。
	Addrs []string
}

// Check は edge.ProbeFunc の形のヘルスチェック。
func (p *FakeProbe) Check(_ context.Context, addr string, _ tls.Certificate, _ *x509.Certificate) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Addrs = append(p.Addrs, addr)
	if p.fail {
		return errors.New("probe failed")
	}
	return nil
}

// SetFail は失敗させるかを変える。
func (p *FakeProbe) SetFail(v bool) {
	p.mu.Lock()
	p.fail = v
	p.mu.Unlock()
}
