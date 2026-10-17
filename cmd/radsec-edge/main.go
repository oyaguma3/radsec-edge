// radsec-edge は RadSec のエッジノードの本体（Web GUI、整合ループ、CRL の取得。設計概要 §5.1）。
// Docker の操作は radsec-edge-agent に頼む。
package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	// distroless のイメージにはタイムゾーンのデータがないので、埋め込んで環境変数 TZ を効かせる。
	_ "time/tzdata"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
	"github.com/oyaguma3/radsec-edge/internal/server"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: radsec-edge <command>

commands:
  serve        サーバーを起動する（コマンド省略時の既定）。起動時に DB のスキーマを移行する
  migrate      DB のスキーマを移行して終わる
  healthcheck  動いている radsec-edge の /healthz を確かめる（compose の healthcheck 用）

設定は環境変数（接頭辞 EDGE_）で与える。
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"serve"}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx)
	case "migrate":
		err = migrate(ctx)
	case "healthcheck":
		err = healthcheck(ctx)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// openDB は設定を読み、DB を開いてスキーマを移行する。
func openDB(ctx context.Context) (config.Config, *slog.Logger, *db.DB, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, nil, nil, err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	log.Info("starting", "version", version, "mode", cfg.Mode)
	file := filepath.Join(cfg.DataDir, "radsec-edge.db")
	d, err := db.Open(ctx, file)
	if err != nil {
		return cfg, log, nil, err
	}
	applied, err := d.Migrate(ctx)
	if err != nil {
		d.Close()
		return cfg, log, nil, err
	}
	v, err := d.SchemaVersion(ctx)
	if err != nil {
		d.Close()
		return cfg, log, nil, err
	}
	log.Info("database", "file", file, "schema_version", v, "applied", applied)
	return cfg, log, d, nil
}

func serve(ctx context.Context) error {
	cfg, log, d, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	svc := edge.New(edge.Options{
		Log: log, DB: d, Agent: agent.NewClient(cfg.AgentSocket),
		Store: rsconf.Store{Root: cfg.TenantsDir}, Keys: keystore.Store{Dir: filepath.Join(cfg.DataDir, "keys")},
		URNPrefix: cfg.URNPrefix, DNSDomain: cfg.DNSDomain, Secret: cfg.Upstream.Secret, CRLBaseURL: cfg.CRLBaseURL,
		ProbeTimeout: cfg.ProbeTimeout,
	})
	log.Info("edge", "tenants_dir", cfg.TenantsDir, "agent_socket", cfg.AgentSocket, "urn_prefix", cfg.URNPrefix,
		"dns_domain", cfg.DNSDomain, "crl_base_url", cfg.CRLBaseURL, "reconcile_interval", cfg.ReconcileInterval.String(),
		"crl_interval", cfg.CRLInterval.String())
	go svc.Run(ctx, cfg.ReconcileInterval, cfg.CRLInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := d.Ping(r.Context()); err != nil {
			http.Error(w, "db is not available", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return server.Run(ctx, server.Options{Addr: cfg.GUIAddr, Handler: mux, Log: log})
}

func migrate(ctx context.Context) error {
	_, _, d, err := openDB(ctx)
	if err != nil {
		return err
	}
	return d.Close()
}

// healthcheck は、同じコンテナで動いている radsec-edge の /healthz を確かめる。
// distroless のイメージには curl がないので、compose の healthcheck はこれを使う。
func healthcheck(ctx context.Context) error {
	_, port, err := net.SplitHostPort(cmp.Or(os.Getenv("EDGE_GUI_ADDR"), ":8447"))
	if err != nil {
		return fmt.Errorf("EDGE_GUI_ADDR: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
