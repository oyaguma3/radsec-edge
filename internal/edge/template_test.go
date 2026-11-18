package edge

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/agent"
	"github.com/oyaguma3/radsec-edge/internal/db"
	"github.com/oyaguma3/radsec-edge/internal/edge/edgetest"
	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
	"github.com/oyaguma3/radsec-edge/internal/rsconf"
)

// tenant は DB のテナントを読み直す。
func (e *env) tenant(t *testing.T, id string) db.Tenant {
	t.Helper()
	tn, err := e.db.Tenant(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

// state はテナントのひな形の状態を返す。
func (e *env) state(t *testing.T, id string) TemplateState {
	t.Helper()
	st, err := e.agent.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return TemplateStateOf(e.tenant(t, id), st)
}

func recreated(calls []string, id string) bool { return slices.Contains(calls, "recreate "+id) }

// 同じタグで新しいイメージを読み込んでも、整合ループと普段の反映はコンテナを作り直さない。今の形へ・前の形へは、選んだときだけ作り直す（§24.14 の U6-1・U6-3・U6-4）。
func TestTemplateLatestAndPrevious(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	a := agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageA}
	b := agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageB}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != a || !PrevRefOf(tn).IsZero() {
		t.Fatalf("recorded after the first apply = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if ts := e.state(t, "tenant-a"); !ts.Current || ts.CanRollback {
		t.Errorf("state after the first apply = %+v", ts)
	}

	// 新しいイメージを読み込んだ（今のタグが ImageB を指し、ImageA は残す）。
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	e.agent.TakeCalls()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); recreated(calls, "tenant-a") {
		t.Errorf("the container was recreated without choosing: %v", calls)
	}
	if ts := e.state(t, "tenant-a"); ts.Current || ts.Recorded != a || ts.Latest != b {
		t.Errorf("state after loading a new image = %+v", ts)
	}

	// 今の形へ。新しいイメージで検査し、作り直し、前の形を記録する。
	e.agent.Validated = nil
	rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest)
	if err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(latest) = %+v, %v", rec, err)
	}
	if !slices.Equal(e.agent.Validated, []string{edgetest.ImageB}) {
		t.Errorf("validated with %v", e.agent.Validated)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != b || PrevRefOf(tn) != a {
		t.Errorf("recorded after latest = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if ts := e.state(t, "tenant-a"); !ts.Current || !ts.CanRollback {
		t.Errorf("state after latest = %+v", ts)
	}
	// もう一度の今の形は作り直さない。
	e.agent.TakeCalls()
	if _, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); recreated(calls, "tenant-a") {
		t.Errorf("recreated again: %v", calls)
	}

	// 前の形へ戻す。前の形は今の形と入れ替わる（もう一度今の形にできる）。
	rec, err = e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious)
	if err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(previous) = %+v, %v", rec, err)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != a || PrevRefOf(tn) != b {
		t.Errorf("recorded after previous = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if ts := e.state(t, "tenant-a"); ts.Current || ts.Running != a {
		t.Errorf("state after previous = %+v", ts)
	}
}

// 今の形でヘルスチェックが通らなければ、元の形で作り直し、記録は変えない（§24.14 の U6-4）。
func TestTemplateLatestRollsBack(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	e.probe.SetFail(true)
	rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest)
	if err == nil || rec.Result != db.ResultRolledBack {
		t.Fatalf("ApplyTemplate(latest) with a failing probe = %+v, %v", rec, err)
	}
	a := agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageA}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != a || !PrevRefOf(tn).IsZero() {
		t.Errorf("recorded after the rollback = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if ts := e.state(t, "tenant-a"); ts.Running != a {
		t.Errorf("the container did not go back: %+v", ts)
	}
}

// 前の形がない・使えないときは断る。
func TestTemplatePreviousUnavailable(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	cause := func(err error) string {
		if ie, ok := errors.AsType[*InputError](err); ok {
			return ie.Cause
		}
		return ""
	}
	if _, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); cause(err) != CauseNoPreviousTemplate {
		t.Errorf("previous without a record = %v", err)
	}
	if _, err := e.svc.StartApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); cause(err) != CauseNoPreviousTemplate {
		t.Errorf("StartApplyTemplate(previous) without a record = %v", err)
	}
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	if _, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest); err != nil {
		t.Fatal(err)
	}
	// 前のイメージを消した。
	e.agent.Images = nil
	e.svc.forgetStatus()
	if _, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); cause(err) != CauseTemplateUnavailable {
		t.Errorf("previous with the image removed = %v", err)
	}
	if _, err := e.svc.StartApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); cause(err) != CauseTemplateUnavailable {
		t.Errorf("StartApplyTemplate(previous) with the image removed = %v", err)
	}
}

// 段階 6 より前に作ったコンテナ（記録がない）は、作り直さずにその形を記録する（§24.14 の U6-5）。
func TestTemplateRecordsRunningContainer(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	// 記録を消して、前の作りの DB と同じにする。今のタグは別のイメージを指している。
	if err := e.db.SetTemplate(ctx, "tenant-a", 0, "", 0, ""); err != nil {
		t.Fatal(err)
	}
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	e.agent.TakeCalls()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); recreated(calls, "tenant-a") {
		t.Errorf("recreated a running container: %v", calls)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != (agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageA}) {
		t.Errorf("recorded = %+v", RefOf(tn))
	}
}

// なくなったコンテナは記録の形で作る。記録のイメージがなければ、今の形で作って記録を改める（止めたままにしない）。
func TestTemplateMissingContainer(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	a := agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageA}
	b := agent.Ref{Template: agent.LatestTemplate, Image: edgetest.ImageB}
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	if err := e.agent.Remove(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if ts := e.state(t, "tenant-a"); ts.Running != a || ts.Recorded != a {
		t.Errorf("recreated with %+v (recorded %+v), want the recorded form", ts.Running, ts.Recorded)
	}
	// 記録のイメージを消してからコンテナがなくなった。
	e.agent.Images = nil
	if err := e.agent.Remove(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != b || PrevRefOf(tn) != a {
		t.Errorf("recorded after the fallback = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if ts := e.state(t, "tenant-a"); ts.Running != b {
		t.Errorf("running after the fallback = %+v", ts.Running)
	}
}

// 設定の書き方が今かを整合ループで計る（反映済みのハッシュが変わるまで計り直さない。§24.14 の U6-2）。
func TestConfigCurrent(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); known {
		t.Error("known before the first apply")
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); !cur || !known {
		t.Errorf("ConfigCurrent after apply = %v, %v", cur, known)
	}
	// 書き方が変わったのと同じ（反映済みのハッシュを別の値にして計り直す）。
	tn := e.tenant(t, "tenant-a")
	if err := e.db.MarkApplied(ctx, tn.ID, tn.AppliedVersion, tn.AppliedRevision, "0000000000000000"+tn.AppliedHash[16:], tn.AppliedPort); err != nil {
		t.Fatal(err)
	}
	e.svc.refreshConfigState(ctx, e.tenant(t, "tenant-a"))
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); cur || !known {
		t.Errorf("ConfigCurrent after the template changed = %v, %v", cur, known)
	}
}

// conf はテナントの今の版の radsecproxy.conf。
func (e *env) conf(t *testing.T, slug string) string {
	t.Helper()
	_, b, err := e.svc.Store.Current(slug)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[rsconf.FileConf])
}

// 版 1 で動くテナント（段階 6-0 の形）は、新しいコードでも版 1 の書き方のまま反映し（IdleTimeout を書かない。古い radsecproxy は
// 知らないオプションとして断る）、今の形（版 2）に反映し直すと IdleTimeout 0 を書き、前の形に戻すと版 1 の書き方に戻る（§24.15）。
func TestTemplateIdleTimeoutByVersion(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	v1 := agent.Ref{Template: 1, Image: edgetest.ImageA}
	if err := e.db.SetTemplate(ctx, "tenant-a", v1.Template, v1.Image, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if c := e.conf(t, "tenant-a"); strings.Contains(c, "IdleTimeout") || !strings.Contains(c, "TCPKeepalive on") {
		t.Errorf("template 1 config:\n%s", c)
	}
	// 新しいイメージを読み込んでも、普段の反映は版 1 の書き方のまま（作り直さない）。設定の書き方は今（版 1 として）。
	e.agent.ImageID, e.agent.Images = edgetest.ImageB, []string{edgetest.ImageA}
	if _, err := e.svc.PutAP(ctx, e.user, "tenant-a", "ap-001", e.apCert(t, "ap-001")); err != nil {
		t.Fatal(err)
	}
	e.agent.TakeCalls()
	if _, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if calls := e.agent.TakeCalls(); recreated(calls, "tenant-a") {
		t.Errorf("recreated without choosing: %v", calls)
	}
	if c := e.conf(t, "tenant-a"); strings.Contains(c, "IdleTimeout") || !strings.Contains(c, "client tenant-a-ap-001 ") {
		t.Errorf("template 1 config after an AP was added:\n%s", c)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); !cur || !known {
		t.Errorf("ConfigCurrent of template 1 = %v, %v", cur, known)
	}
	if ts := e.state(t, "tenant-a"); ts.Current || ts.Recorded != v1 {
		t.Errorf("state of template 1 = %+v", ts)
	}

	// 今の形へ。版 2 の書き方（client ブロックごとに IdleTimeout 0）を新しいイメージで検査して作り直す。
	v2 := agent.Ref{Template: 2, Image: edgetest.ImageB}
	e.agent.Validated = nil
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(latest) = %+v, %v", rec, err)
	}
	c := e.conf(t, "tenant-a")
	if n := strings.Count(c, "\n    IdleTimeout 0\n"); n != strings.Count(c, "\nclient ") || n != 2 {
		t.Errorf("IdleTimeout 0 in %d blocks:\n%s", n, c)
	}
	if !slices.Equal(e.agent.Validated, []string{edgetest.ImageB}) {
		t.Errorf("validated with %v", e.agent.Validated)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != v2 || PrevRefOf(tn) != v1 {
		t.Errorf("recorded after latest = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); !cur || !known {
		t.Errorf("ConfigCurrent of template 2 = %v, %v", cur, known)
	}

	// 前の形へ戻すと、版 1 の書き方を前のイメージで検査して作り直す。
	e.agent.Validated = nil
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(previous) = %+v, %v", rec, err)
	}
	if c := e.conf(t, "tenant-a"); strings.Contains(c, "IdleTimeout") {
		t.Errorf("config after previous:\n%s", c)
	}
	if !slices.Equal(e.agent.Validated, []string{edgetest.ImageA}) {
		t.Errorf("validated with %v", e.agent.Validated)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != v1 || PrevRefOf(tn) != v2 {
		t.Errorf("recorded after previous = %+v / %+v", RefOf(tn), PrevRefOf(tn))
	}

	// 前のイメージを消してからコンテナがなくなると、整合ループは今の形（版 2）で作る（§24.14 の U6-3）。設定は版 1 の書き方のまま
	// （1.11.5-pc2 は版 1 の書き方も読める）なので「設定の書き方が古い」と出て、次の反映で版 2 の書き方になる。
	e.agent.Images = nil
	if err := e.agent.Remove(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != v2 {
		t.Errorf("recorded after the fallback = %+v", RefOf(tn))
	}
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); cur || !known {
		t.Errorf("ConfigCurrent after the fallback = %v, %v", cur, known)
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil || rec.Action != "restart" {
		t.Fatalf("Apply after the fallback = %+v, %v", rec, err)
	}
	if c := e.conf(t, "tenant-a"); !strings.Contains(c, "\n    IdleTimeout 0\n") {
		t.Errorf("config after the fallback and apply:\n%s", c)
	}
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if cur, known := e.svc.ConfigCurrent(e.tenant(t, "tenant-a")); !cur || !known {
		t.Errorf("ConfigCurrent after the apply = %v, %v", cur, known)
	}
}

// agent が作れるひな形の版と、rsconf が描ける設定の書き方の版は同じ（パッケージを分けているので、ここで確かめる）。
func TestTemplatesMatch(t *testing.T) {
	if !slices.Equal(agent.Templates, rsconf.Templates) || !slices.Contains(agent.Templates, agent.LatestTemplate) {
		t.Errorf("agent.Templates = %v (latest %d), rsconf.Templates = %v", agent.Templates, agent.LatestTemplate, rsconf.Templates)
	}
}

// このコードが作れない版を記録したテナント（新しいコードの DB を戻したなど）は、設定を描く前に断る。
func TestTemplateUnknownVersion(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if err := e.db.SetTemplate(ctx, "tenant-a", 9, edgetest.ImageA, 0, ""); err != nil {
		t.Fatal(err)
	}
	rec, err := e.svc.Apply(ctx, e.user, "tenant-a")
	if ie, ok := errors.AsType[*InputError](err); !ok || ie.Cause != CauseTemplateUnavailable || rec.Result != db.ResultFailed {
		t.Errorf("Apply with template 9 = %+v, %v", rec, err)
	}
}

// apCert は tenant-a の AP の証明書（PEM）を発行する。
func (e *env) apCert(t *testing.T, name string) []byte {
	t.Helper()
	_, key := pkitest.NewKeyPair(t)
	csr, err := pki.NewCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	_, certPEM := e.ca.SignCSR(t, pkitest.Leaf{CN: "tenant-a-" + name, URI: names.SANURI("example", "tenant-a", name)}, csr)
	return certPEM
}
