package history

import (
	"fmt"
	"strings"
)

// DiffLine is one line of a diff: Op is ' ', '-' or '+'.
type DiffLine struct {
	Op   byte
	Text string
}

// Diff returns the changed lines between a and b with context lines around
// each change, as unified diffs show them. An unchanged pair returns nil.
// Hunks are separated by a DiffLine with Op '@'.
func Diff(a, b string, context int) []DiffLine {
	if a == b {
		return nil
	}
	x := splitLines(a)
	y := splitLines(b)
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			switch {
			case x[i] == y[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var all []DiffLine
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case x[i] == y[j]:
			all = append(all, DiffLine{' ', x[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			all = append(all, DiffLine{'-', x[i]})
			i++
		default:
			all = append(all, DiffLine{'+', y[j]})
			j++
		}
	}
	for ; i < len(x); i++ {
		all = append(all, DiffLine{'-', x[i]})
	}
	for ; j < len(y); j++ {
		all = append(all, DiffLine{'+', y[j]})
	}
	keep := make([]bool, len(all))
	for k, l := range all {
		if l.Op == ' ' {
			continue
		}
		for c := k - context; c <= k+context; c++ {
			if c >= 0 && c < len(all) {
				keep[c] = true
			}
		}
	}
	var out []DiffLine
	for k, l := range all {
		if !keep[k] {
			continue
		}
		if k > 0 && !keep[k-1] && len(out) > 0 {
			out = append(out, DiffLine{Op: '@'})
		}
		out = append(out, l)
	}
	return out
}

// FormatDiff renders a Diff as text, one prefixed line each.
func FormatDiff(lines []DiffLine) string {
	var b strings.Builder
	for _, l := range lines {
		if l.Op == '@' {
			b.WriteString("@@\n")
			continue
		}
		_, _ = fmt.Fprintf(&b, "%c%s\n", l.Op, l.Text)
	}
	return b.String()
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
