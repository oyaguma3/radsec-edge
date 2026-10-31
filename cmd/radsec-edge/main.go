// radsec-edge は RadSec のエッジノードの本体（Web GUI、整合ループ、CRL の取得。設計概要 §5.1）。
// Docker の操作は radsec-edge-agent に頼む。
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
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

	"github.com/oyaguma3/radsec-edge/internal/access"
	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/api"
	"github.com/oyaguma3/radsec-edge/internal/audit"
	"github.com/oyaguma3/radsec-edge/internal/auth"
	"github.com/oyaguma3/radsec-edge/internal/certs"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge"
	"github.com/oyaguma3/radsec-edge/internal/keystore"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
	"github.com/oyaguma3/radsec-edge/internal/server"
	"github.com/oyaguma3/radsec-edge/internal/web"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: radsec-edge <command>

commands:
  serve        サーバーを起動する（コマンド省略時の既定）。起動時に DB のスキーマを移行する
  migrate      DB のスキーマを移行して終わる
  server-cert  管理API のサーバー証明書（なければ作る）を標準出力に、フィンガープリントを標準エラーに出す（管理モード）
  replace-server-cert  管理API のサーバー証明書を作り直して標準出力に出す（動いているサーバーは SIGHUP で読み直す。管理モード）
  healthcheck  動いている radsec-edge の /healthz を確かめる（compose の healthcheck 用）

設定は環境変数（接頭辞 EDGE_）で与える。管理クライアントのピンとサーバー証明書は SIGHUP で読み直す。
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
	case "server-cert":
		err = serverCert(os.Stdout, os.Stderr)
	case "replace-server-cert":
		err = replaceServerCert(ctx, os.Stdout, os.Stderr)
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
	// ログは標準エラーに出す（コマンドの標準出力に証明書を出すものがあるため。Docker は両方をコンテナのログにする）。
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
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
	d.SetAuditSink(audit.NewFiles(cfg.AuditDir, cfg.AuditRetentionDays))
	return cfg, log, d, nil
}

func serve(ctx context.Context) error {
	cfg, log, d, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := audit.CheckWritableDir(cfg.AuditDir); err != nil {
		return err
	}
	if cfg.Mode == config.ModeManaged {
		if err := checkManagedTenants(ctx, d); err != nil {
			return err
		}
	}
	svc := edge.New(edge.Options{
		Log: log, DB: d, Agent: agent.NewClient(cfg.AgentSocket),
		Store: rsconf.Store{Root: cfg.TenantsDir}, Keys: keystore.Store{Dir: filepath.Join(cfg.DataDir, "keys")},
		URNPrefix: cfg.URNPrefix, DNSDomain: cfg.DNSDomain, Secret: cfg.Upstream.Secret, CRLBaseURL: cfg.CRLBaseURL,
		ProbeTimeout: cfg.ProbeTimeout, ApplyTimeout: cfg.ApplyTimeout, Capacity: cfg.TenantCapacity,
		Stamp: rsconf.Stamp{VendorID: cfg.StampVendorID, VendorType: cfg.StampVendorType},
	})
	log.Info("edge", "tenants_dir", cfg.TenantsDir, "agent_socket", cfg.AgentSocket, "urn_prefix", cfg.URNPrefix,
		"dns_domain", cfg.DNSDomain, "crl_base_url", cfg.CRLBaseURL, "reconcile_interval", cfg.ReconcileInterval.String(),
		"crl_interval", cfg.CRLInterval.String(), "tenant_capacity", cfg.TenantCapacity,
		"stamp_vendor_id", cfg.StampVendorID, "stamp_vendor_type", cfg.StampVendorType)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go svc.Run(ctx, cfg.ReconcileInterval, cfg.CRLInterval)
	go maintain(ctx, log, d, audit.NewFiles(cfg.AuditDir, cfg.AuditRetentionDays))

	ident, err := newIdentifier(ctx, cfg, log)
	if err != nil {
		return err
	}
	h, err := web.New(web.Options{Log: log, Version: version, Mode: cfg.Mode, DB: d, Edge: svc, Identifier: ident,
		AuthUpstream: cfg.Upstream.Auth, AcctUpstream: cfg.Upstream.Acct, CRLWarn: cfg.CRLWarn, ApplyTimeout: cfg.ApplyTimeout})
	if err != nil {
		return err
	}
	runs := []func(context.Context) error{
		func(ctx context.Context) error {
			// 画面から待つ反映は、構文検査とヘルスチェックを含めて時間がかかるので、上限を長くする。
			return server.Run(ctx, server.Options{Addr: cfg.GUIAddr, Handler: h.Routes(), Log: log.With("listener", "gui"),
				WriteTimeout: max(3*time.Minute, cfg.ApplyTimeout+time.Minute)})
		},
		func(ctx context.Context) error {
			<-ctx.Done()
			// 裏の反映を取り消し、前の版に戻すのを待つ（compose の stop_grace_period は 20 秒。§24.11 の EA5）。
			svc.Shutdown(shutdownWait)
			return nil
		},
	}
	// 管理API は管理モードだけ待ち受ける（§12.1）。
	if cfg.Mode == config.ModeManaged {
		run, reload, err := apiRunner(cfg, log, d, svc)
		if err != nil {
			return err
		}
		runs = append(runs, run)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					reload()
				}
			}
		}()
	}
	return runAll(ctx, cancel, runs...)
}

// shutdownWait は停止のときに裏の反映を待つ時間。
const shutdownWait = 15 * time.Second

// checkManagedTenants は、管理モードでは数字でない ID のテナント（単独モードで作ったもの）があれば起動しない（§6、§24.11 の EA4）。
func checkManagedTenants(ctx context.Context, d *db.DB) error {
	tenants, err := d.Tenants(ctx)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		if !names.ValidManagedID(t.ID) {
			return fmt.Errorf("tenant %q was created in standalone mode; managed mode cannot take it over (remove the tenants in standalone mode, or start with an empty data directory)", t.ID)
		}
	}
	return nil
}

// maintain は、監査ログのファイルと冪等の記録を、起動のときと 1 時間ごとに整理する。
func maintain(ctx context.Context, log *slog.Logger, d *db.DB, f *audit.Files) {
	for {
		if err := f.Maintain(time.Now()); err != nil {
			log.Error("cannot maintain audit files", "event_id", "EDGE_AUDIT_FILE_ERR", "error", err)
		}
		if _, err := d.PurgeIdempotency(ctx); err != nil && ctx.Err() == nil {
			log.Warn("cannot purge idempotency records", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// apiRunner は管理API（mTLS）のリスナーと、SIGHUP で動かす読み直しを用意する。サーバー証明書がなければ自己署名で作る（§12.1）。
func apiRunner(cfg config.Config, log *slog.Logger, d *db.DB, svc *edge.Service) (func(context.Context) error, func(), error) {
	pins, err := api.LoadPins(cfg.AdminClientsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("admin clients: %w", err)
	}
	certPath, keyPath := filepath.Join(cfg.TLSDir, "server.pem"), filepath.Join(cfg.TLSDir, "server.key")
	if created, err := certs.EnsureFiles(certPath, keyPath, cfg.TLSHosts); err != nil {
		return nil, nil, err
	} else if created {
		log.Info("created a self-signed server certificate for the management API", "hosts", cfg.TLSHosts)
	}
	f, err := certs.LoadFile(certPath, keyPath, log)
	if err != nil {
		return nil, nil, err
	}
	log.Info("management API", "fingerprint", certs.Fingerprint(f.Leaf()), "not_after", f.Leaf().NotAfter, "admin_clients", pins.Names())
	apiLog := log.With("listener", "api")
	h := &api.Handler{Log: apiLog, DB: d, Edge: svc, Version: version, Mode: cfg.Mode, CRLWarn: cfg.CRLWarn, MgmtClient: pins.NameFromRequest, AdminClients: pins.Names}
	run := func(ctx context.Context) error {
		return api.Run(ctx, api.ListenOptions{Addr: cfg.AdminAddr, GetCertificate: f.GetCertificate, Pins: pins, Handler: h.Routes(), Log: apiLog})
	}
	// 読み直しは、それぞれ失敗したら前のまま続ける。
	reload := func() {
		if err := pins.Reload(); err != nil {
			log.Error("failed to reload admin clients (keeping the previous ones)", "event_id", "EDGE_ADMIN_CLIENTS_RELOAD_ERR", "error", err.Error())
		} else {
			log.Info("reloaded admin clients", "event_id", "EDGE_ADMIN_CLIENTS_RELOADED", "admin_clients", pins.Names(), "fingerprints", pins.Fingerprints())
		}
		if err := f.Reload(); err != nil {
			log.Error("failed to reload server certificate (keeping the previous one)", "event_id", "EDGE_SERVER_CERT_RELOAD_ERR", "error", err.Error())
		} else {
			log.Info("reloaded server certificate", "event_id", "EDGE_SERVER_CERT_RELOADED", "fingerprint", certs.Fingerprint(f.Leaf()), "not_after", f.Leaf().NotAfter)
		}
	}
	return run, reload, nil
}

// runAll は fns を並べて動かし、最初のものが終わったら残りも止めて待つ。
func runAll(ctx context.Context, cancel context.CancelFunc, fns ...func(context.Context) error) error {
	errc := make(chan error, len(fns))
	for _, fn := range fns {
		go func() { errc <- fn(ctx) }()
	}
	first := <-errc
	cancel()
	for range len(fns) - 1 {
		if err := <-errc; first == nil {
			first = err
		}
	}
	return first
}

// serverCert は管理API のサーバー証明書（なければ作る）を標準出力に、フィンガープリントを標準エラーに出す。
func serverCert(stdout, stderr io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Mode != config.ModeManaged {
		return errors.New("the management API is only used in managed mode (EDGE_MODE=managed)")
	}
	certPath, keyPath := filepath.Join(cfg.TLSDir, "server.pem"), filepath.Join(cfg.TLSDir, "server.key")
	created, err := certs.EnsureFiles(certPath, keyPath, cfg.TLSHosts)
	if err != nil {
		return err
	}
	f, err := certs.LoadFile(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	stdout.Write(b)
	if created {
		fmt.Fprintf(stderr, "サーバー証明書を作りました（SAN: %v）。\n", cfg.TLSHosts)
	}
	fmt.Fprintf(stderr, "SHA-256 フィンガープリント: %s（有効期限 %s）\n", certs.Fingerprint(f.Leaf()), f.Leaf().NotAfter.Local().Format(time.DateOnly))
	return nil
}

// replaceServerCert は管理API のサーバー証明書を作り直す（SAN は EDGE_TLS_HOSTS）。新しい証明書を標準出力に出す。
// 動いているサーバーは SIGHUP で読み直す。監査ログに残す。
func replaceServerCert(ctx context.Context, stdout, stderr io.Writer) error {
	cfg, _, d, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer d.Close()
	if cfg.Mode != config.ModeManaged {
		return errors.New("the management API is only used in managed mode (EDGE_MODE=managed)")
	}
	certPath, keyPath := filepath.Join(cfg.TLSDir, "server.pem"), filepath.Join(cfg.TLSDir, "server.key")
	certPEM, err := certs.Replace(certPath, keyPath, cfg.TLSHosts)
	if err != nil {
		return err
	}
	f, err := certs.LoadFile(certPath, keyPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	fp := certs.Fingerprint(f.Leaf())
	if err := d.InsertAudit(ctx, db.AuditEntry{Operator: "cli", Source: db.SourceSystem, Action: "server-cert.replace", Target: fp,
		Detail: map[string]any{"hosts": cfg.TLSHosts, "not_after": f.Leaf().NotAfter.UTC().Format(time.RFC3339)}}); err != nil {
		return err
	}
	stdout.Write(certPEM)
	fmt.Fprintf(stderr, "サーバー証明書を作り直しました（SAN: %v）。SHA-256 フィンガープリント: %s（有効期限 %s）。SIGHUP を送ると新しい証明書を使います。\n",
		cfg.TLSHosts, fp, f.Leaf().NotAfter.Local().Format(time.DateOnly))
	return nil
}

// newIdentifier は、要求から利用者を決める方法を作る（Cloudflare Access の JWT、または開発用の設定）。
func newIdentifier(ctx context.Context, cfg config.Config, log *slog.Logger) (auth.Identifier, error) {
	if cfg.DevMode() {
		log.Warn("development mode: requests are not authenticated; every request acts as the development user "+
			"(EDGE_DEV_USER_EMAIL). Do not use this setting in production", "email", cfg.DevUserEmail, "addr", cfg.GUIAddr)
		return auth.Dev(cfg.DevUserEmail), nil
	}
	v, err := access.New(access.Options{TeamDomain: cfg.AccessTeamDomain, AUDs: cfg.AccessAUDs,
		HTTPClient: &http.Client{Timeout: 10 * time.Second}})
	if err != nil {
		return nil, err
	}
	// 公開鍵を先に取得しておく。取得できなくても起動は続ける（最初の要求のときにもう一度試みる）。
	if n, err := v.Refresh(ctx); err != nil {
		log.Warn("cannot fetch Cloudflare Access public keys; will retry on the first request", "url", v.CertsURL(), "error", err)
	} else {
		log.Info("cloudflare access", "team_domain", cfg.AccessTeamDomain, "auds", len(cfg.AccessAUDs), "keys", n)
	}
	return auth.Access(v), nil
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
