package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/docker"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// maxLogLines はログの末尾の行数の上限。maxLogBytes は返すログの大きさの上限。
const (
	maxLogLines = 5000
	maxLogBytes = 4 << 20
)

// Server は agent の API。
type Server struct {
	log     *slog.Logger
	version string
	docker  *docker.Client
	// tenantsDir はテナントのディレクトリのホストのパス、network はテナントのコンテナを置くネットワーク。
	tenantsDir  string
	network     string
	publishAddr string
	// mu はコンテナの作成・作り直し・削除を 1 つずつにする（同じテナントのコンテナを 2 つ作らないように）。
	mu sync.Mutex
}

// ServerOptions は Server の設定。
type ServerOptions struct {
	Log        *slog.Logger
	Version    string
	Docker     *docker.Client
	TenantsDir string
	Network    string
	// PublishAddr はテナントのポートを公開するホストのアドレス（空ならすべてのアドレス）。
	PublishAddr string
}

// NewServer は Server を作る。
func NewServer(o ServerOptions) *Server {
	return &Server{log: o.Log, version: o.Version, docker: o.Docker, tenantsDir: o.TenantsDir, network: o.Network, publishAddr: o.PublishAddr}
}

// Routes は API のハンドラーを返す。
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/tenants/{id}/ensure", s.ensure)
	mux.HandleFunc("POST /v1/tenants/{id}/restart", s.restart)
	mux.HandleFunc("POST /v1/tenants/{id}/stop", s.stop)
	mux.HandleFunc("POST /v1/tenants/{id}/remove", s.remove)
	mux.HandleFunc("POST /v1/tenants/{id}/signal", s.signal)
	mux.HandleFunc("GET /v1/tenants/{id}/logs", s.logs)
	mux.HandleFunc("POST /v1/validate", s.validate)
	return s.accessLog(mux)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		if r.Method == http.MethodGet {
			level = slog.LevelDebug // 状態とログの読み出しは整合ループが定期的に呼ぶ
		}
		s.log.Log(r.Context(), level, "request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(), "trace_id", r.Header.Get("X-Trace-ID"))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.MarshalWrite(w, v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// fail は Docker のエラーを応答にする（コンテナがなければ 404）。
func (s *Server) fail(w http.ResponseWriter, r *http.Request, op string, err error) {
	if errors.Is(err, ErrNotFound) || errors.Is(err, docker.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.log.Error(op, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusBadGateway, op+": "+err.Error())
}

// readJSON は要求の本文を読む（64 KB まで。知らない項目は断る）。
func readJSON(r *http.Request, v any) error {
	return json.UnmarshalRead(io.LimitReader(r.Body, 64<<10), v, json.RejectUnknownMembers(true))
}

// tenantID はパスのテナントの ID を検証して返す。
func tenantID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !names.ValidSlug(id) {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return "", false
	}
	return id, true
}

// find はテナントのコンテナ（ラベルで識別）を返す。なければ ErrNotFound。2 つ以上あれば、最初のものを返す。
func (s *Server) find(ctx context.Context, id string) (docker.Summary, error) {
	cs, err := s.docker.List(ctx, LabelTenant+"="+id)
	if err != nil {
		return docker.Summary{}, err
	}
	if len(cs) == 0 {
		return docker.Summary{}, ErrNotFound
	}
	return cs[0], nil
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st := Status{Version: s.version, Image: Image, Network: s.network, Containers: []Container{}}
	ctx := r.Context()
	if err := s.docker.Ping(ctx); err != nil {
		st.DockerError = err.Error()
		writeJSON(w, http.StatusOK, st)
		return
	}
	st.DockerOK = true
	var err error
	if st.ImagePresent, err = s.docker.ImageExists(ctx, Image); err != nil {
		s.fail(w, r, "inspect image", err)
		return
	}
	if st.NetworkPresent, err = s.docker.NetworkExists(ctx, s.network); err != nil {
		s.fail(w, r, "inspect network", err)
		return
	}
	if st.NetworkPresent {
		if st.NetworkSubnets, err = s.docker.NetworkSubnets(ctx, s.network); err != nil {
			s.fail(w, r, "inspect network", err)
			return
		}
	}
	cs, err := s.docker.List(ctx, LabelTenant)
	if err != nil {
		s.fail(w, r, "list containers", err)
		return
	}
	for _, c := range cs {
		in, err := s.docker.InspectContainer(ctx, c.ID)
		if errors.Is(err, docker.ErrNotFound) {
			continue // 一覧と詳しい状態の間に消えた
		}
		if err != nil {
			s.fail(w, r, "inspect container", err)
			return
		}
		ct := Container{
			TenantID: c.Labels[LabelTenant], Slug: c.Labels[LabelSlug], Name: strings.TrimPrefix(in.Name, "/"), ID: in.ID,
			State: in.State.Status, Running: in.State.Running, Restarting: in.State.Restarting,
			RestartCount: in.RestartCount, ExitCode: in.State.ExitCode,
		}
		if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil && t.Year() > 1 {
			ct.StartedAt = t
		}
		if p, err := strconv.Atoi(c.Labels[LabelPort]); err == nil && names.ValidSlug(ct.Slug) {
			ct.Port = p
			ct.SpecCurrent = tenantSpec(s.tenantsDir, s.network, s.publishAddr, ct.TenantID, ct.Slug, p).Labels[LabelSpec] == c.Labels[LabelSpec]
		}
		st.Containers = append(st.Containers, ct)
	}
	writeJSON(w, http.StatusOK, st)
}

// ensure はテナントのコンテナを固定のひな形から作り、起動する（あって動いていれば何もしない）。
// ひな形やポートが違うコンテナは作り直す。
func (s *Server) ensure(w http.ResponseWriter, r *http.Request) {
	id, ok := tenantID(w, r)
	if !ok {
		return
	}
	var req EnsureRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if !names.ValidSlug(req.Slug) || req.Port < PortMin || req.Port > PortMax {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("slug must follow the naming rule and port must be between %d and %d", PortMin, PortMax))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	want := tenantSpec(s.tenantsDir, s.network, s.publishAddr, id, req.Slug, req.Port)
	action := EnsureCreated
	cur, err := s.find(ctx, id)
	switch {
	case err == nil && cur.Labels[LabelSpec] == want.Labels[LabelSpec] && cur.Labels[LabelSlug] == req.Slug:
		if cur.State == "running" {
			writeJSON(w, http.StatusOK, EnsureResult{Action: EnsureNone})
			return
		}
		if err := s.docker.Start(ctx, cur.ID); err != nil {
			s.fail(w, r, "start", err)
			return
		}
		s.log.Info("tenant container started", "tenant", id, "container", cur.ID)
		writeJSON(w, http.StatusOK, EnsureResult{Action: EnsureStarted})
		return
	case err == nil:
		if err := s.docker.Remove(ctx, cur.ID); err != nil && !errors.Is(err, docker.ErrNotFound) {
			s.fail(w, r, "remove", err)
			return
		}
		action = EnsureRecreated
	case !errors.Is(err, ErrNotFound):
		s.fail(w, r, "list", err)
		return
	}
	// 同じ名前のコンテナ（ラベルの違う、前のテナントの残りなど）があれば、作るのに失敗する。ラベルのないコンテナには触れない。
	cid, err := s.docker.Create(ctx, ContainerName(req.Slug), want)
	if err != nil {
		s.fail(w, r, "create", err)
		return
	}
	if err := s.docker.Start(ctx, cid); err != nil {
		s.fail(w, r, "start", err)
		return
	}
	s.log.Info("tenant container "+action, "tenant", id, "slug", req.Slug, "port", req.Port, "container", cid)
	writeJSON(w, http.StatusOK, EnsureResult{Action: action})
}

// onContainer は、テナントのコンテナに対して op を行う。
func (s *Server) onContainer(w http.ResponseWriter, r *http.Request, name string, op func(ctx context.Context, id string) error) {
	tid, ok := tenantID(w, r)
	if !ok {
		return
	}
	c, err := s.find(r.Context(), tid)
	if err != nil {
		s.fail(w, r, name, err)
		return
	}
	if err := op(r.Context(), c.ID); err != nil {
		s.fail(w, r, name, err)
		return
	}
	s.log.Info("tenant container "+name, "tenant", tid, "container", c.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	s.onContainer(w, r, "restart", func(ctx context.Context, id string) error { return s.docker.Restart(ctx, id, stopTimeout) })
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	s.onContainer(w, r, "stop", func(ctx context.Context, id string) error { return s.docker.Stop(ctx, id, stopTimeout) })
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onContainer(w, r, "remove", s.docker.Remove)
}

// signal は HUP だけを送る（CA と CRL の読み直し。§18.1）。
func (s *Server) signal(w http.ResponseWriter, r *http.Request) {
	var req SignalRequest
	if err := readJSON(r, &req); err != nil || req.Signal != "HUP" {
		writeError(w, http.StatusBadRequest, "only HUP is allowed")
		return
	}
	s.onContainer(w, r, "signal", func(ctx context.Context, id string) error { return s.docker.Kill(ctx, id, "HUP") })
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	opts := docker.LogsOptions{Tail: 200, Timestamps: q.Get("timestamps") == "1"}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC 3339 date-time")
			return
		}
		// 時刻を指定したら、その後の行をすべて返す（大きさは maxLogBytes で切る）。
		opts.Since, opts.Tail = t, 0
	}
	if v := q.Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLogLines {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("lines must be between 1 and %d", maxLogLines))
			return
		}
		opts.Tail = n
	}
	c, err := s.find(r.Context(), tid)
	if err != nil {
		s.fail(w, r, "logs", err)
		return
	}
	out, err := s.docker.Logs(r.Context(), c.ID, opts, maxLogBytes)
	if err != nil {
		s.fail(w, r, "logs", err)
		return
	}
	writeJSON(w, http.StatusOK, LogsResult{Logs: out})
}

// validate は、捨てるコンテナで radsecproxy -p の構文検査を行う（§10.1、§18.1 の V3）。
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if !names.ValidSlug(req.Slug) || !rsconf.ValidGen(req.Gen) {
		writeError(w, http.StatusBadRequest, "invalid slug or generation")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), validateTimeout)
	defer cancel()
	var rnd [4]byte
	rand.Read(rnd[:])
	name := "radsec-edge-validate-" + req.Slug + "-" + hex.EncodeToString(rnd[:])
	cid, err := s.docker.Create(ctx, name, validateSpec(s.tenantsDir, s.network, req.Slug, req.Gen))
	if err != nil {
		s.fail(w, r, "validate: create", err)
		return
	}
	// 途中で失敗しても、捨てるコンテナは必ず消す。
	defer s.docker.Remove(context.WithoutCancel(ctx), cid)
	if err := s.docker.Start(ctx, cid); err != nil {
		s.fail(w, r, "validate: start", err)
		return
	}
	code, err := s.docker.Wait(ctx, cid)
	if err != nil {
		s.fail(w, r, "validate: wait", err)
		return
	}
	out, err := s.docker.Logs(ctx, cid, docker.LogsOptions{Tail: 200}, 64<<10)
	if err != nil {
		s.fail(w, r, "validate: logs", err)
		return
	}
	s.log.Info("validate", "slug", req.Slug, "gen", req.Gen, "exit_code", code)
	writeJSON(w, http.StatusOK, ValidateResult{OK: code == 0, Output: out})
}

// Cleanup は、前に動いていた agent が残した構文検査の捨てるコンテナを消す（起動のときに呼ぶ）。
func (s *Server) Cleanup(ctx context.Context) error {
	cs, err := s.docker.List(ctx, LabelValidate)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range cs {
		if err := s.docker.Remove(ctx, c.ID); err != nil && !errors.Is(err, docker.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
