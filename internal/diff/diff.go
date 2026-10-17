// Package diff は、2 つの文章の行の差分を作る（画面で、反映済みの設定と未反映の設定の差分を出す。設計概要 §11.1）。
// Myers の方法（O((N+M)D)）で最短の編集を求める。生成した設定は AP の名前の順に並ぶので、差分は小さい。
package diff

import (
	"strings"
)

// Op は行の操作。
type Op byte

const (
	Equal  Op = ' '
	Insert Op = '+'
	Delete Op = '-'
)

// Line は差分の 1 行。
type Line struct {
	Op   Op
	Text string
}

// Lines は a から b への行の差分を返す。
func Lines(a, b string) []Line {
	x, y := split(a), split(b)
	n, m := len(x), len(y)
	max := n + m
	off := max + 1
	v := make([]int, 2*max+2)
	var trace [][]int
	for d := 0; d <= max; d++ {
		trace = append(trace, append([]int(nil), v...))
		for k := -d; k <= d; k += 2 {
			var i int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				i = v[off+k+1]
			} else {
				i = v[off+k-1] + 1
			}
			j := i - k
			for i < n && j < m && x[i] == y[j] {
				i, j = i+1, j+1
			}
			v[off+k] = i
			if i >= n && j >= m {
				return backtrack(x, y, trace, off)
			}
		}
	}
	return nil // ここには来ない
}

// backtrack は記録した各段の v から、編集の列を後ろからたどって作る。
func backtrack(x, y []string, trace [][]int, off int) []Line {
	var out []Line
	i, j := len(x), len(y)
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		k := i - j
		var pk int
		if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		pi := v[off+pk]
		pj := pi - pk
		for i > pi && j > pj {
			i, j = i-1, j-1
			out = append(out, Line{Equal, x[i]})
		}
		if d > 0 {
			if i == pi {
				j--
				out = append(out, Line{Insert, y[j]})
			} else {
				i--
				out = append(out, Line{Delete, x[i]})
			}
		}
	}
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return out
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// Hunk は、変わった行とその前後の行のまとまり。
type Hunk struct {
	// OldStart と NewStart は、まとまりの最初の行の番号（1 から）。
	OldStart, NewStart int
	Lines              []Line
}

// Hunks は差分を、変わった行の前後 context 行を含むまとまりに分ける。変わった行がなければ空。
func Hunks(lines []Line, context int) []Hunk {
	var out []Hunk
	oldNo, newNo := 1, 1
	type pos struct{ old, new int }
	positions := make([]pos, len(lines))
	for i, l := range lines {
		positions[i] = pos{oldNo, newNo}
		switch l.Op {
		case Equal:
			oldNo, newNo = oldNo+1, newNo+1
		case Delete:
			oldNo++
		case Insert:
			newNo++
		}
	}
	i := 0
	for i < len(lines) {
		if lines[i].Op == Equal {
			i++
			continue
		}
		start := max(0, i-context)
		end := i
		// 変わった行が context*2 行以内に続けば、同じまとまりにする。
		for end < len(lines) {
			if lines[end].Op != Equal {
				end++
				continue
			}
			next := end
			for next < len(lines) && lines[next].Op == Equal {
				next++
			}
			if next < len(lines) && next-end <= 2*context {
				end = next
				continue
			}
			end = min(len(lines), end+context)
			break
		}
		out = append(out, Hunk{OldStart: positions[start].old, NewStart: positions[start].new, Lines: lines[start:end]})
		i = end
	}
	return out
}
