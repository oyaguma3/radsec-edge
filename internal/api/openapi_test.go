package api

import (
	"bufio"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestOpenAPIRoutes は、実装の口（Routes）と docs/openapi/edge-api.yaml のパスとメソッドが一致することを確かめる。
// YAML の読み込みは外部依存を増やさないよう、paths の下の 2 段の字下げだけを読む。
func TestOpenAPIRoutes(t *testing.T) {
	f, err := os.Open("../../docs/openapi/edge-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pathRe := regexp.MustCompile(`^  (/.*):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	var spec []string
	inPaths, cur := false, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && line != "" && !strings.HasPrefix(line, " "):
			inPaths = false
		case inPaths && pathRe.MatchString(line):
			cur = pathRe.FindStringSubmatch(line)[1]
		case inPaths && methodRe.MatchString(line):
			spec = append(spec, strings.ToUpper(methodRe.FindStringSubmatch(line)[1])+" "+cur)
		}
	}
	var impl []string
	for _, r := range Routes {
		impl = append(impl, r.Method+" "+r.Path)
	}
	slices.Sort(spec)
	slices.Sort(impl)
	if !slices.Equal(spec, impl) {
		t.Errorf("OpenAPI and the implementation differ:\nOpenAPI: %v\nimpl:    %v", spec, impl)
	}
	// 変更の口は Idempotency-Key が必須（OpenAPI でも IdempotencyKey を参照する）。
	for _, r := range Routes {
		if r.idempotent != (r.Method != "GET") {
			t.Errorf("%s %s: idempotent = %v", r.Method, r.Path, r.idempotent)
		}
	}
}
