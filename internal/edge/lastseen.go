package edge

import (
	"bufio"
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// radsecproxy のログの行（LogLevel 2。設計概要 §18.1 の V4）。
//
//	tlsservernew: TLS connection from <IP>, client <名前>, subject CN=<CN>, TLSv1.3 ... up
//	tlsserverrd: connection from <IP>, client <名前> lost
//	verify error: num=<番号>:<理由>:depth=0:CN=<CN>
//
// client の名前は NAS-Identifier（§10.3）。拒否の行の「SSL accept from <名前>」の名前は送信元 IP が一致した最初の client で、
// 証明書の持ち主ではないので使わず、直前の verify error の CN（AP の証明書の CN は NAS-Identifier）で持ち主を決める。
var (
	upPattern     = regexp.MustCompile(`TLS connection from ([^,\s]+), client ([^,\s]+),.*\bup\s*$`)
	lostPattern   = regexp.MustCompile(`connection from ([^,\s]+), client ([^,\s]+) lost\s*$`)
	rejectPattern = regexp.MustCompile(`verify error: .*\bCN\s*=\s*([^,/\s]+)`)
)

// parseSeen は、Docker の時刻を先頭に付けたログ（agent の LogsSince）から、AP とグループの接続の出来事を読む。nasToAP は
// ブロックの名前と証明書の CN から AP かグループの名前を引く（ヘルスチェック用の probe と、登録のない名前は読み飛ばす）。
// 共通のブロックの接続は、送信元の IP ごとの出来事にする（§24.3）。最後に読んだ行の時刻を返す。
func parseSeen(logs string, nasToAP map[string]string) ([]db.SeenEvent, time.Time) {
	var out []db.SeenEvent
	var last time.Time
	sc := bufio.NewScanner(strings.NewReader(logs))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		ts, line, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		last = at
		switch {
		case upPattern.MatchString(line):
			m := upPattern.FindStringSubmatch(line)
			if m[2] == rsconf.SharedBlock {
				out = append(out, db.SeenEvent{Shared: true, Kind: db.SeenUp, At: at, IP: m[1]})
			} else if ap, ok := nasToAP[m[2]]; ok {
				out = append(out, db.SeenEvent{AP: ap, Kind: db.SeenUp, At: at, IP: m[1]})
			}
		case lostPattern.MatchString(line):
			m := lostPattern.FindStringSubmatch(line)
			if m[2] == rsconf.SharedBlock {
				out = append(out, db.SeenEvent{Shared: true, Kind: db.SeenDown, At: at, IP: m[1]})
			} else if ap, ok := nasToAP[m[2]]; ok {
				out = append(out, db.SeenEvent{AP: ap, Kind: db.SeenDown, At: at})
			}
		case rejectPattern.MatchString(line):
			m := rejectPattern.FindStringSubmatch(line)
			if ap, ok := nasToAP[m[1]]; ok {
				out = append(out, db.SeenEvent{AP: ap, Kind: db.SeenReject, At: at})
			}
		}
	}
	return out, last
}

// RefreshLastSeen は、動いているテナントのコンテナのログの続きを読み、AP の接続の状態を書き換える（§12.1）。
// 初めて読むテナントは、コンテナが起動したところから読む（その前の接続は、もう切れている）。
func (s *Service) RefreshLastSeen(ctx context.Context) error {
	st, err := s.Agent.Status(ctx)
	if err != nil {
		return err
	}
	tenants, err := s.DB.Tenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		c, ok := st.Container(t.ID)
		if !ok || !c.Running {
			continue
		}
		if err := s.refreshSeen(ctx, t, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) refreshSeen(ctx context.Context, t db.Tenant, c agent.Container) error {
	since, err := s.DB.LogCursor(ctx, t.ID)
	if err != nil {
		return err
	}
	// コンテナを起動し直すと切断の行は出ないので、共通のブロックの接続の数を数え直す。
	restarted := false
	if start := c.StartedAt.Add(-time.Second); since.Before(start) {
		since, restarted = start, true
	}
	logs, err := s.Agent.LogsSince(ctx, t.ID, since)
	if err != nil {
		return err
	}
	aps, err := s.DB.APs(ctx, t.ID)
	if err != nil {
		return err
	}
	nasToAP := map[string]string{}
	for _, a := range aps {
		nasToAP[names.NASIdentifier(t.Slug, a.Name)] = a.Name
		if a.Kind == db.KindGroup {
			nasToAP[rsconf.GroupBlock(a.Name)] = a.Name
		}
	}
	events, last := parseSeen(logs, nasToAP)
	if last.IsZero() {
		return nil
	}
	return s.DB.ApplySeen(ctx, t.ID, events, last, restarted)
}

// SeenState は画面に出す AP の接続の状態。
type SeenState struct {
	db.Seen
	// Known は記録があるか。Up は今つながっているか（コンテナを起動した後に接続して、切断していない）。
	Known, Up bool
}

// SharedSeen はテナントの共通のブロックの接続の状態を、最後の接続の新しい順に返す。コンテナの起動より前の接続は切れたものとして扱う。
func (s *Service) SharedSeen(ctx context.Context, tenantID string, startedAt time.Time) ([]db.SharedSeen, error) {
	seen, err := s.DB.SharedSeens(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range seen {
		if startedAt.IsZero() || seen[i].LastUp.Before(startedAt.Add(-time.Second)) {
			seen[i].Connections = 0
		}
	}
	return seen, nil
}

// APSeen はテナントの AP の接続の状態を返す。コンテナを再起動すると切断の行は出ないので、コンテナの起動より前の接続は
// 切れたものとして扱う（startedAt がゼロなら、コンテナがない・止まっているので、すべて切れている）。
func (s *Service) APSeen(ctx context.Context, tenantID string, startedAt time.Time) (map[string]SeenState, error) {
	seen, err := s.DB.Seen(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := map[string]SeenState{}
	for ap, v := range seen {
		out[ap] = SeenState{Seen: v, Known: true, Up: v.Connected && !startedAt.IsZero() && v.LastUp.After(startedAt.Add(-time.Second))}
	}
	return out, nil
}
