package rotator

import (
	"fmt"
	"io"
	"strings"
)

// RotateEach rotates the keys named, one after another, as `sshmgr rotate`
// does for a selection: a key that fails is reported and left as it was, and
// the rest go on. save runs after every committed key, so an interrupted batch
// keeps what it finished. It returns the keys not rotated.
func (r *Rotator) RotateEach(names []string, allowUnverified bool, pw string, out io.Writer,
	save func() error) ([]string, error) {
	var failed []string
	for _, n := range names {
		report, err := r.Rotate(n, allowUnverified, pw)
		switch {
		case err != nil:
			failed = append(failed, n)
			_, _ = fmt.Fprintf(out, "rotation FAILED: %s\n  %v\n", n, err)
			continue
		case report.Committed:
			if err := save(); err != nil {
				return failed, err
			}
		default:
			failed = append(failed, n)
		}
		_, _ = fmt.Fprintln(out, report.Format())
	}
	_, _ = fmt.Fprintf(out, "%d of %d key(s) rotated", len(names)-len(failed), len(names))
	if len(failed) > 0 {
		_, _ = fmt.Fprintf(out, "; not rotated (left as they were): %s\n", strings.Join(failed, ", "))
		return failed, nil
	}
	_, _ = fmt.Fprintln(out)
	return nil, nil
}
