// radsec-edge-agent は、Docker Engine を操作する唯一の部品（設計概要 §10）。
// radsec-edge から unix ソケットで決まった操作だけを受け付け、テナントの radsecproxy のコンテナを固定のひな形で作る。
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/config"
	"github.com/oyaguma3/radsec-edge/internal/docker"
	"github.com/oyaguma3/radsec-edge/internal/server"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

const usage = `usage: radsec-edge-agent [serve]

設定は環境変数（接頭辞 EDGE_）で与える。
`

func main() {
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context) error {
	cfg, err := config.LoadAgent()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	log.Info("starting", "version", version, "image", agent.Image, "network", cfg.Network, "tenants_dir", cfg.TenantsDir,
		"publish_addr", cfg.PublishAddr)

	d := docker.New(cfg.DockerSocket)
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if err := d.Ping(pingCtx); err != nil {
		// Docker に届かなくても起動は続ける（状態の問い合わせで Docker の誤りを返す）。
		log.Error("cannot reach the Docker Engine", "socket", cfg.DockerSocket, "error", err)
	}
	cancel()
	srv := agent.NewServer(agent.ServerOptions{Log: log, Version: version, Docker: d, TenantsDir: cfg.TenantsDir, Network: cfg.Network,
		PublishAddr: cfg.PublishAddr, FluentdAddress: cfg.FluentdAddress})
	cleanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if err := srv.Cleanup(cleanCtx); err != nil {
		log.Warn("cannot remove leftover validation containers", "error", err)
	}
	cancel()

	ln, err := listen(cfg.Socket, cfg.SocketGID)
	if err != nil {
		return err
	}
	defer os.Remove(cfg.Socket)
	return server.Serve(ctx, ln, server.Options{Addr: cfg.Socket, Handler: srv.Routes(), Log: log})
}

// listen は unix ソケットで待ち受ける。前に残ったソケットは消す。radsec-edge（グループ gid）だけがつなげるよう、
// 権限を 0660 にし、グループを gid にする（設計概要 §10.2）。
func listen(path string, gid int) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Lchown(path, -1, gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chown %s to group %d: %w", path, gid, err)
	}
	return ln, nil
}
