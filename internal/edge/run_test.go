package edge

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// errNoSocket は、ホストの再起動の直後に agent のソケットがまだないときの誤り。
var errNoSocket = errors.New("dial unix /run/radsec-edge-agent/agent.sock: connect: no such file or directory")

// offsets は時刻の並びを start からの秒にする。
func offsets(ts []time.Time, start time.Time) []int {
	var out []int
	for _, t := range ts {
		out = append(out, int(t.Sub(start)/time.Second))
	}
	return out
}

// 起動のときに agent に届かなければ、届くまで 5 秒ごとにやり直し、止まっていたテナントのコンテナを次の周回（1 分後）を待たずに起こす
// （aka-mvpset の R6-4。§24.15）。ホストの再起動では radsec-edge が agent より先に起き、CRL の更新で SIGHUP を受けたテナントのコンテナは
// Docker では起き上がらない（T5-15）。
func TestRunRetriesUntilAgent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.readyTenant(t, "tenant-a")
		if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
			t.Fatal(err)
		}
		// ホストを再起動した（テナントのコンテナは止まっていて、agent のソケットはまだない）。12 秒目に agent が起きる。
		if err := e.agent.Stop(ctx, "tenant-a"); err != nil {
			t.Fatal(err)
		}
		e.agent.SetFailStatus(errNoSocket)
		start, before := time.Now(), len(e.agent.StatusCalls())
		done := make(chan struct{})
		go func() { e.svc.Run(ctx, time.Minute, time.Hour); close(done) }()
		time.Sleep(12 * time.Second)
		e.agent.SetFailStatus(nil)
		time.Sleep(8 * time.Second)
		synctest.Wait()
		calls := offsets(e.agent.StatusCalls()[before:], start)
		st, _ := e.agent.Status(ctx)
		if c, ok := st.Container("tenant-a"); !ok || !c.Running {
			t.Errorf("the tenant container is not running 20 s after start: %+v", c)
		}
		// 0・5・10 秒目に届かず、15 秒目の整合で起こした（同じ時刻の 2 回目は AP の最後の接続の読み取り）。
		if !slices.Equal(calls, []int{0, 5, 10, 15, 15}) {
			t.Errorf("Status was called at %v s", calls)
		}
		if rec := e.svc.LastReconcile(); rec.Error != "" || rec.At.Sub(start) != 15*time.Second {
			t.Errorf("last reconcile = %+v (%s after start)", rec, rec.At.Sub(start))
		}
		cancel()
		<-done
	})
}

// agent に届かないまま 2 分を過ぎたら、短い間隔のやり直しをやめ、いつもの間隔に戻る。
func TestRunRetriesAtMostTwoMinutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.agent.SetFailStatus(errNoSocket)
		start := time.Now()
		done := make(chan struct{})
		go func() { e.svc.Run(ctx, time.Minute, time.Hour); close(done) }()
		time.Sleep(200 * time.Second)
		synctest.Wait()
		var want []int
		for s := 0; s <= 120; s += 5 {
			want = append(want, s)
		}
		want = append(want, 120, 180, 180) // 120 秒目にやめて AP の最後の接続を読み、次は 1 分後
		if got := offsets(e.agent.StatusCalls(), start); !slices.Equal(got, want) {
			t.Errorf("Status was called at %v s, want %v", got, want)
		}
		cancel()
		<-done
	})
}
