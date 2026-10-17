package diff

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// apply は差分を a に当てて b を作り直す（差分が正しいことの確かめ）。
func apply(lines []Line) (string, string) {
	var a, b []string
	for _, l := range lines {
		switch l.Op {
		case Equal:
			a, b = append(a, l.Text), append(b, l.Text)
		case Delete:
			a = append(a, l.Text)
		case Insert:
			b = append(b, l.Text)
		}
	}
	return strings.Join(a, "\n"), strings.Join(b, "\n")
}

func TestLines(t *testing.T) {
	got := Lines("a\nb\nc\n", "a\nx\nc\nd\n")
	want := []Line{{Equal, "a"}, {Delete, "b"}, {Insert, "x"}, {Equal, "c"}, {Insert, "d"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Lines = %v", got)
	}
	if got := Lines("", "a\n"); len(got) != 1 || got[0].Op != Insert {
		t.Errorf("Lines(empty) = %v", got)
	}
	if got := Lines("a\n", "a\n"); len(got) != 1 || got[0].Op != Equal {
		t.Errorf("Lines(same) = %v", got)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		gen := func() string {
			var s []string
			for range r.IntN(30) {
				s = append(s, string(rune('a'+r.IntN(4))))
			}
			return strings.Join(s, "\n")
		}
		a, b := gen(), gen()
		ga, gb := apply(Lines(a, b))
		if ga != a || gb != b {
			t.Fatalf("Lines(%q, %q) does not reproduce the inputs", a, b)
		}
	}
}

func TestHunks(t *testing.T) {
	var a, b []string
	for i := range 40 {
		a = append(a, fmt.Sprint(i))
		b = append(b, fmt.Sprint(i))
	}
	b[5] = "x"
	b[8] = "y"
	b[30] = "z"
	hs := Hunks(Lines(strings.Join(a, "\n"), strings.Join(b, "\n")), 3)
	if len(hs) != 2 {
		t.Fatalf("Hunks = %d, want 2: %v", len(hs), hs)
	}
	if hs[0].OldStart != 3 || hs[1].OldStart != 28 {
		t.Errorf("starts = %d, %d", hs[0].OldStart, hs[1].OldStart)
	}
	if len(Hunks(Lines("a", "a"), 3)) != 0 {
		t.Error("Hunks(same) is not empty")
	}
}
