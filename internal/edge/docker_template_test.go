package edge

import (
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/agent"
)

// derivedImage は radsecproxy のイメージにラベルを足しただけの別のイメージ（ID が違う）を作り、tag を付けて ID を返す。
// 後で、そのイメージのコンテナとタグ（agent が付けた残すタグを含む）を消す。
func derivedImage(t *testing.T, tag string) string {
	t.Helper()
	var rnd [4]byte
	rand.Read(rnd[:])
	cmd := exec.Command("docker", "build", "-q", "-t", tag, "-")
	cmd.Stdin = strings.NewReader("FROM " + agent.Image + "\nLABEL radsec-edge.test=" + hex.EncodeToString(rnd[:]) + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker build %s: %v", tag, err)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "ancestor="+id).Output()
		for c := range strings.FieldsSeq(string(ids)) {
			exec.Command("docker", "rm", "-f", c).Run()
		}
		tags, _ := exec.Command("docker", "image", "inspect", "-f", `{{join .RepoTags " "}}`, id).Output()
		for tg := range strings.FieldsSeq(string(tags)) {
			exec.Command("docker", "rmi", tg).Run()
		}
		exec.Command("docker", "rmi", id).Run()
	})
	return id
}

// 本物の Docker で、前の形（別のイメージ）へ作り直し、そのイメージのタグがなくなっても残すタグで戻せる。
// 動いているコンテナは、記録と違っても整合ループで作り直さない（§24.14 の U6-1・U6-3〜U6-5）。
func TestDockerTemplate(t *testing.T) {
	e := dockerEnv(t)
	ctx := t.Context()
	e.readyTenant(t, "tenant-a")
	if _, err := e.svc.UpdateTenant(ctx, e.user, "tenant-a", TenantInput{Port: 20991, Auth: authUp, Acct: acctUp}); err != nil {
		t.Fatal(err)
	}
	if rec, err := e.svc.Apply(ctx, e.user, "tenant-a"); err != nil {
		t.Fatalf("Apply = %+v, %v", rec, err)
	}
	st, err := e.svc.Agent.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orig := st.Latest()
	if tn := e.tenant(t, "tenant-a"); RefOf(tn) != orig {
		t.Fatalf("recorded = %+v, want %+v", RefOf(tn), orig)
	}
	var rnd [3]byte
	rand.Read(rnd[:])
	tag := agent.ImageRepo + ":test-" + hex.EncodeToString(rnd[:])
	derived := agent.Ref{Template: 1, Image: derivedImage(t, tag)}

	// 前の形を、別のイメージにしておく（新しい版の radsecproxy を入れた後で戻す場面と同じ）。
	if err := e.db.SetTemplate(ctx, "tenant-a", orig.Template, orig.Image, derived.Template, derived.Image); err != nil {
		t.Fatal(err)
	}
	running := func() (agent.Ref, string) {
		t.Helper()
		st, err := e.svc.Agent.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, ok := st.Container("tenant-a")
		if !ok {
			t.Fatal("no container")
		}
		return c.Ref(), c.ID
	}
	_, id0 := running()
	if err := e.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, id := running(); id != id0 {
		t.Error("the reconciler recreated a running container")
	}
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(previous) = %+v, %v", rec, err)
	}
	if r, _ := running(); r != derived {
		t.Errorf("running after previous = %+v, want %+v", r, derived)
	}
	// そのイメージのタグを外す（同じタグで別のイメージを読み込んだのと同じ）。使っているので残すタグが付く。
	if out, err := exec.Command("docker", "rmi", "-f", tag).CombinedOutput(); err != nil {
		t.Fatalf("untag: %v\n%s", err, out)
	}
	e.svc.ForgetAgentStatus()
	if st, err = e.svc.AgentStatus(ctx); err != nil {
		t.Fatal(err)
	}
	keep := agent.ImageRepo + ":" + agent.KeepTagPrefix + agent.ShortImage(derived.Image)
	if !slices.ContainsFunc(st.Images, func(im agent.ImageInfo) bool { return im.ID == derived.Image && slices.Contains(im.Tags, keep) }) {
		t.Errorf("the image in use is not kept: %+v", st.Images)
	}
	// 元の形に戻し（前の形は残すタグのイメージ）、もう一度前の形にする。
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(previous) back = %+v, %v", rec, err)
	}
	if r, _ := running(); r != orig {
		t.Errorf("running after going back = %+v, want %+v", r, orig)
	}
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplatePrevious); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(previous) with the kept image = %+v, %v", rec, err)
	}
	if r, _ := running(); r != derived {
		t.Errorf("running with the kept image = %+v", r)
	}
	// 今の形へ。
	if rec, err := e.svc.ApplyTemplate(ctx, e.user, "tenant-a", TemplateLatest); err != nil || rec.Action != agent.EnsureRecreated {
		t.Fatalf("ApplyTemplate(latest) = %+v, %v", rec, err)
	}
	if st, err = e.svc.Agent.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if ts := TemplateStateOf(e.tenant(t, "tenant-a"), st); !ts.Current || ts.Running != orig || !ts.CanRollback || ts.Previous != derived {
		t.Errorf("state after latest = %+v", ts)
	}
}
