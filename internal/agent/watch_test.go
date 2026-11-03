package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestWatchDocker(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	errDown := errors.New("connection refused")
	t.Run("届かないまま limit を過ぎると誤りで終わる", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			err := WatchDocker(t.Context(), log, func(context.Context) error { return errDown }, 10*time.Second, time.Minute)
			if !errors.Is(err, errDown) {
				t.Fatalf("err = %v", err)
			}
			// 最初に届かなかった 10 秒目から 60 秒を過ぎた 70 秒目に終わる。
			if d := time.Since(start); d != 70*time.Second {
				t.Errorf("returned after %s", d)
			}
		})
	})
	t.Run("途中で届けば数え直す", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var n atomic.Int32
			ping := func(context.Context) error {
				// 5 回目だけ届く（10〜40 秒目と 60 秒目以降は届かない）。
				if n.Add(1) == 5 {
					return nil
				}
				return errDown
			}
			start := time.Now()
			err := WatchDocker(t.Context(), log, ping, 10*time.Second, time.Minute)
			if err == nil {
				t.Fatal("err = nil")
			}
			if d := time.Since(start); d != 120*time.Second {
				t.Errorf("returned after %s, want 120s (counting again from 60s)", d)
			}
		})
	})
	t.Run("届いている間と ctx が終わったときは nil", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
			defer cancel()
			if err := WatchDocker(ctx, log, func(context.Context) error { return nil }, 10*time.Second, time.Minute); err != nil {
				t.Errorf("err = %v", err)
			}
		})
	})
}
