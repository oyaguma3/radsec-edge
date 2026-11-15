package edge

import (
	"context"
	"errors"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
)

// TemplateMode は反映のときのコンテナのひな形の扱い（設計概要 §24.14 の U6-4）。
type TemplateMode string

const (
	// TemplateKeep は記録のひな形を保つ（普段の反映。まだ記録がなければ今の形で作る）。
	TemplateKeep TemplateMode = ""
	// TemplateLatest は今の形（最新のひな形の版と、今のタグのイメージ）へ作り直す。
	TemplateLatest TemplateMode = "latest"
	// TemplatePrevious は 1 つ前の形へ戻す。
	TemplatePrevious TemplateMode = "previous"
)

// ParseTemplateMode は管理API と画面の値を読む（空は TemplateKeep）。
func ParseTemplateMode(s string) (TemplateMode, bool) {
	switch m := TemplateMode(s); m {
	case TemplateKeep, TemplateLatest, TemplatePrevious:
		return m, true
	}
	return "", false
}

// 誤りの理由の符号（ひな形）。
const (
	// CauseNoPreviousTemplate は、前の形の記録がない（前の形に戻せない）。
	CauseNoPreviousTemplate = "NO_PREVIOUS_TEMPLATE"
	// CauseTemplateUnavailable は、求めたひな形が使えない（イメージがホストにない、このコードでは作れない版）。
	CauseTemplateUnavailable = "TEMPLATE_UNAVAILABLE"
)

// RefOf はテナントの記録のひな形（記録がなければ零値）。
func RefOf(t db.Tenant) agent.Ref { return agent.Ref{Template: t.Template, Image: t.ImageID} }

// PrevRefOf はテナントの 1 つ前の形（なければ零値）。
func PrevRefOf(t db.Tenant) agent.Ref {
	return agent.Ref{Template: t.PrevTemplate, Image: t.PrevImageID}
}

// TemplateState はテナントのコンテナのひな形の状態（管理API と画面に出す。§24.14 の U6-7）。
type TemplateState struct {
	// Recorded は記録のひな形（記録がなければ、動いているコンテナの形か、零値）。Latest は今の形。
	Recorded, Latest, Previous agent.Ref
	// Current は記録が今の形と同じで、コンテナも記録どおりに動いているか。Running はコンテナが動いている形（なければ零値）。
	Current bool
	Running agent.Ref
	// Mismatch は、コンテナが記録と違う形で動いているか（反映が途中で止まった、DB を戻したなど）。
	Mismatch bool
	// CanRollback は前の形に戻せるか（前の形の記録があり、そのイメージがホストにあり、その版をこのコードが作れる）。
	CanRollback bool
}

// TemplateStateOf はテナントのひな形の状態を返す。st は agent の状態（取れなければゼロ値で、Current は false）。
func TemplateStateOf(t db.Tenant, st agent.Status) TemplateState {
	out := TemplateState{Recorded: RefOf(t), Latest: st.Latest(), Previous: PrevRefOf(t)}
	c, exists := st.Container(t.ID)
	if exists {
		out.Running = c.Ref()
	}
	if out.Recorded.IsZero() && exists && c.Template != 0 {
		out.Recorded = c.Ref() // まだ記録していない（次の整合ループで記録する）
	}
	out.Mismatch = exists && !out.Recorded.IsZero() && out.Running != out.Recorded
	out.Current = !out.Recorded.IsZero() && st.ImageID != "" && out.Recorded == out.Latest && !out.Mismatch
	out.CanRollback = !out.Previous.IsZero() && agent.KnownTemplate(out.Previous.Template) && hasImage(st, out.Previous.Image)
	return out
}

func hasImage(st agent.Status, id string) bool {
	for _, im := range st.Images {
		if im.ID == id {
			return true
		}
	}
	return false
}

// recorded はテナントのコンテナを作るときのひな形を返す。記録があればそれ、なければ動いているコンテナの形（記録する）、それもなければ今の形。
// 段階 6 より前に作ったコンテナは、ここで作り直さずに記録する（§24.14 の U6-5）。呼び出し側でテナントの排他を取る。
func (s *Service) recorded(ctx context.Context, t db.Tenant, st agent.Status) agent.Ref {
	if r := RefOf(t); !r.IsZero() {
		return r
	}
	if c, ok := st.Container(t.ID); ok && c.Template != 0 && c.ImageID != "" {
		if err := s.DB.SetTemplate(ctx, t.ID, c.Template, c.ImageID, 0, ""); err != nil {
			s.Log.Error("cannot record the template of the container", "tenant", t.ID, "error", err)
		} else {
			s.Log.Info("recorded the template of the running container", "tenant", t.ID, "template", c.Template, "image", agent.ShortImage(c.ImageID))
		}
		return c.Ref()
	}
	return st.Latest()
}

// unusable は、agent がひな形を使えないと返したか（イメージがない・作れない版）。
func unusable(err error) bool {
	return errors.Is(err, agent.ErrImageNotAllowed) || errors.Is(err, agent.ErrUnknownTemplate)
}

// configKey は設定の書き方が今かの写しの鍵（反映済みのハッシュと望む状態の版が変われば計り直す）。
type configKey struct {
	appliedHash string
	desired     int64
}

type configEntry struct {
	key     configKey
	current bool
	known   bool
}

// ConfigCurrent は、未反映の変更がないのに今のコードの書き方で描くと反映済みと違うか（違えば false）を返す。
// known が false なら分からない（未反映の変更がある、まだ反映していない、まだ計っていない）。計るのは整合ループ（refreshConfigState）。
func (s *Service) ConfigCurrent(t db.Tenant) (current, known bool) {
	if t.Pending() || t.AppliedHash == "" {
		return false, false
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	e, ok := s.cfgState[t.ID]
	if !ok || e.key != (configKey{t.AppliedHash, t.DesiredVersion}) {
		return false, false
	}
	return e.current, e.known
}

// refreshConfigState は、写しがないか古いテナントについて、今のコードの書き方で描いて反映済みと比べる（§24.14 の U6-2）。
// 書き方はコードを上げたときにしか変わらないので、反映済みのハッシュか望む状態の版が変わったときだけ計り直す。
func (s *Service) refreshConfigState(ctx context.Context, t db.Tenant) {
	if t.Pending() || t.AppliedHash == "" {
		return
	}
	key := configKey{t.AppliedHash, t.DesiredVersion}
	s.cfgMu.Lock()
	e, ok := s.cfgState[t.ID]
	s.cfgMu.Unlock()
	if ok && e.key == key {
		return
	}
	e = configEntry{key: key}
	if b, err := s.render(ctx, t); err == nil {
		e.current, e.known = b.Hash() == t.AppliedHash, true
	}
	s.cfgMu.Lock()
	s.cfgState[t.ID] = e
	s.cfgMu.Unlock()
}

// forgetConfigState は消したテナントの写しを捨てる。
func (s *Service) forgetConfigState(id string) {
	s.cfgMu.Lock()
	delete(s.cfgState, id)
	s.cfgMu.Unlock()
}
