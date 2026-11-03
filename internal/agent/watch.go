package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Docker の見張りの間隔と、届かないまま待つ長さ（aka-mvpset の verify/edge-long の確認事項 L12）。
const (
	dockerWatchInterval = 10 * time.Second
	dockerWatchLimit    = 60 * time.Second
)

// WatchDocker は interval ごとに ping で Docker Engine を確かめ、limit の間ずっと届かなければ誤りを返す（ctx が終われば nil）。
// agent は docker.sock をファイルとしてマウントするので、dockerd がソケットを作り直すと古いソケットを見たままになり、
// live-restore で agent も止まらないため自分では直らない。誤りで終了すれば、再起動の方針で作り直されて新しいソケットをマウントする。
func WatchDocker(ctx context.Context, log *slog.Logger, ping func(context.Context) error, interval, limit time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	var since time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, interval)
		err := ping(pctx)
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil:
			if !since.IsZero() {
				log.Info("reached the Docker Engine again", "after", time.Since(since).Round(time.Second).String())
				since = time.Time{}
			}
		case since.IsZero():
			since = time.Now()
			log.Warn("cannot reach the Docker Engine", "error", err)
		case time.Since(since) >= limit:
			return fmt.Errorf("the Docker Engine has been unreachable for %s (exiting so that the container is restarted with the current socket): %w", limit, err)
		}
	}
}

// WatchDockerDefault は既定の間隔と長さで WatchDocker を動かす。
func WatchDockerDefault(ctx context.Context, log *slog.Logger, ping func(context.Context) error) error {
	return WatchDocker(ctx, log, ping, dockerWatchInterval, dockerWatchLimit)
}
