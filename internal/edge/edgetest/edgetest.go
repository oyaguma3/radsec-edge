// Package edgetest は、edge と画面の試験で使う偽物の agent とヘルスチェックを提供する。
package edgetest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	// ValidateOK は Validate の結果、FailEnsure は Ensure の誤り。
	ValidateOK bool
	FailEnsure error
}

// NewFakeAgent は偽物の agent を作る。
func NewFakeAgent() *FakeAgent {
	return &FakeAgent{Containers: map[string]*agent.Container{}, LogsText: map[string]string{}, ValidateOK: true}
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
	st := agent.Status{DockerOK: true, ImagePresent: true, NetworkPresent: true}
	for _, c := range f.Containers {
		st.Containers = append(st.Containers, *c)
	}
	return st, nil
}

func (f *FakeAgent) Ensure(_ context.Context, id, slug string, port int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("ensure " + id)
	if f.FailEnsure != nil {
		return "", f.FailEnsure
	}
	c, ok := f.Containers[id]
	switch {
	case !ok:
		f.Containers[id] = &agent.Container{TenantID: id, Slug: slug, Name: agent.ContainerName(slug), State: "running", Running: true, Port: port, SpecCurrent: true}
		return agent.EnsureCreated, nil
	case c.Port != port:
		c.Port, c.Running, c.State = port, true, "running"
		return agent.EnsureRecreated, nil
	case !c.Running:
		c.Running, c.State = true, "running"
		return agent.EnsureStarted, nil
	}
	return agent.EnsureNone, nil
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
func (f *FakeAgent) Validate(_ context.Context, slug, gen string) (agent.ValidateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call("validate " + slug)
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
