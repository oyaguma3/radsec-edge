package edge

import (
	"testing"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/db"
)

// radsecproxy 1.11.2 の LogLevel 2 の行（設計概要 §18.1 の V4。段階 3 の結合の試験で見た形）。先頭は Docker の時刻。
const sampleLogs = `2027-01-15T08:00:00.000000001Z Fri Jan 15 08:00:00 2027: Global LogLevel 2
2027-01-15T08:00:01.000000000Z Fri Jan 15 08:00:01 2027: tlsservernew: TLS connection from 172.18.0.1, client tenant-a-ap-001, subject CN=tenant-a-ap-001, TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 up
2027-01-15T08:00:02.000000000Z Fri Jan 15 08:00:02 2027: tlsservernew: TLS connection from 172.18.0.1, client tenant-a-probe, subject CN=tenant-a-probe, TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 up
2027-01-15T08:00:03.000000000Z Fri Jan 15 08:00:03 2027: verify error: num=23:certificate revoked:depth=0:CN=tenant-a-ap-002
2027-01-15T08:00:03.000000001Z Fri Jan 15 08:00:03 2027: tlsservernew: SSL accept from tenant-a-ap-001 (172.18.0.1) failed: error:0A000086:SSL routines::certificate verify failed
2027-01-15T08:00:04.000000000Z Fri Jan 15 08:00:04 2027: tlsserverrd: connection from 172.18.0.1, client tenant-a-ap-001 lost
2027-01-15T08:00:05.000000000Z Fri Jan 15 08:00:05 2027: tlsservernew: TLS connection from 172.18.0.9, client tenant-a-unknown, subject CN=x, TLSv1.3 up
not a log line
`

func TestParseSeen(t *testing.T) {
	events, last := parseSeen(sampleLogs, map[string]string{"tenant-a-ap-001": "ap-001", "tenant-a-ap-002": "ap-002"})
	want := []struct {
		ap   string
		kind db.SeenKind
		ip   string
	}{{"ap-001", db.SeenUp, "172.18.0.1"}, {"ap-002", db.SeenReject, ""}, {"ap-001", db.SeenDown, ""}}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for i, w := range want {
		if e := events[i]; e.AP != w.ap || e.Kind != w.kind || e.IP != w.ip {
			t.Errorf("event %d = %+v, want %+v", i, e, w)
		}
	}
	if !last.Equal(time.Date(2027, 1, 15, 8, 0, 5, 0, time.UTC)) {
		t.Errorf("last = %v", last)
	}
}

func TestRefreshLastSeen(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", nil)
	e.svc.PutAP(ctx, e.user, "tenant-a", "ap-002", nil)
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2027, 1, 15, 7, 59, 0, 0, time.UTC)
	e.agent.Containers["tenant-a"].StartedAt = started
	e.agent.LogsText["tenant-a"] = sampleLogs
	if err := e.svc.RefreshLastSeen(ctx); err != nil {
		t.Fatal(err)
	}
	// 初めて読むときは、コンテナの起動の少し前から読む。
	if got := e.agent.Since[0]; !got.Equal(started.Add(-time.Second)) {
		t.Errorf("first since = %v", got)
	}
	seen, err := e.svc.APSeen(ctx, "tenant-a", started)
	if err != nil {
		t.Fatal(err)
	}
	if a := seen["ap-001"]; !a.Known || a.Up || a.LastIP != "172.18.0.1" || a.LastDown.IsZero() {
		t.Errorf("ap-001 = %+v", a)
	}
	if b := seen["ap-002"]; b.LastReject.IsZero() {
		t.Errorf("ap-002 = %+v", b)
	}
	// 次は前回の続き（最後の行の時刻）から読む。
	e.agent.LogsText["tenant-a"] = "2027-01-15T09:00:00Z x: tlsservernew: TLS connection from 172.18.0.2, client tenant-a-ap-001, subject CN=tenant-a-ap-001, TLSv1.3 up\n"
	if err := e.svc.RefreshLastSeen(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.agent.Since[1]; !got.Equal(time.Date(2027, 1, 15, 8, 0, 5, 0, time.UTC)) {
		t.Errorf("second since = %v", got)
	}
	seen, _ = e.svc.APSeen(ctx, "tenant-a", started)
	if a := seen["ap-001"]; !a.Up || a.LastIP != "172.18.0.2" {
		t.Errorf("ap-001 after reconnect = %+v", a)
	}
	// コンテナを起動し直したら、その前の接続は切れたものとして扱う。
	seen, _ = e.svc.APSeen(ctx, "tenant-a", time.Date(2027, 1, 15, 10, 0, 0, 0, time.UTC))
	if seen["ap-001"].Up {
		t.Error("a connection before the restart is shown as up")
	}
	// 止まっているコンテナは読まない。
	e.agent.Containers["tenant-a"].Running = false
	n := len(e.agent.Since)
	e.svc.RefreshLastSeen(ctx)
	if len(e.agent.Since) != n {
		t.Error("logs of a stopped container were read")
	}
}

// グループはブロックの名前（grp-<グループ>）と CN（<slug>-<グループ>）で引く。共通のブロックは送信元の IP ごとの出来事にする（§24.3）。
func TestParseSeenGroupAndShared(t *testing.T) {
	logs := `2027-01-15T08:00:01.000000000Z Fri Jan 15 08:00:01 2027: tlsservernew: TLS connection from 192.0.2.7, client grp-unifi, subject CN=tenant-a-unifi, TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 up
2027-01-15T08:00:02.000000000Z Fri Jan 15 08:00:02 2027: verify error: num=23:certificate revoked:depth=0:CN=tenant-a-unifi
2027-01-15T08:00:03.000000000Z Fri Jan 15 08:00:03 2027: tlsservernew: TLS connection from 198.51.100.9, client shared, subject CN=aabbccddeeff, TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 up
2027-01-15T08:00:04.000000000Z Fri Jan 15 08:00:04 2027: tlsserverrd: connection from 198.51.100.9, client shared lost
2027-01-15T08:00:05.000000000Z Fri Jan 15 08:00:05 2027: tlsserverrd: connection from 192.0.2.7, client grp-unifi lost
2027-01-15T08:00:06.000000000Z Fri Jan 15 08:00:06 2027: verify error: num=23:certificate revoked:depth=0:CN=aabbccddeeff
`
	events, _ := parseSeen(logs, map[string]string{"tenant-a-unifi": "unifi", "grp-unifi": "unifi"})
	want := []db.SeenEvent{
		{AP: "unifi", Kind: db.SeenUp, IP: "192.0.2.7"},
		{AP: "unifi", Kind: db.SeenReject},
		{Shared: true, Kind: db.SeenUp, IP: "198.51.100.9"},
		{Shared: true, Kind: db.SeenDown, IP: "198.51.100.9"},
		{AP: "unifi", Kind: db.SeenDown},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for i, w := range want {
		e := events[i]
		if e.AP != w.AP || e.Shared != w.Shared || e.Kind != w.Kind || e.IP != w.IP {
			t.Errorf("event %d = %+v, want %+v", i, e, w)
		}
	}
}
