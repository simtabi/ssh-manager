package cli

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/overview"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/version"
)

// The banner answers the three questions someone opening an interactive session
// has to answer before any menu entry means anything: what binary is this, where
// is it about to operate, and what state is that place in.
//
// The middle one is not decoration. Both the config home and ~/.ssh are
// overridable by environment variable, so an unlabelled menu gives no way to
// tell a session pointed at a sandbox from one pointed at the real tree - and
// every entry below "Change ~/.ssh" rewrites whichever it happens to be.
//
// It is plain text with no colour, like the rest of the tool: escapes are
// forbidden by TestNoSourceEmitsTerminalEscapes, because output that a pipe
// cannot read is a different product. Attention is carried by a "!" in the first
// column instead, which survives being piped into a file.

// bannerRow is one line of the state block. A row with a fix is a problem, and
// prints with a leading "!" and the command that resolves it - so the report and
// the remedy are never in two different places.
type bannerRow struct {
	label string
	value string
	fix   string // the command that would fix it; empty when the row is just a fact
}

func (r bannerRow) String() string {
	mark := " "
	if r.fix != "" {
		mark = "!"
	}
	if r.fix == "" {
		return fmt.Sprintf("%s %-9s %s", mark, r.label, r.value)
	}
	return fmt.Sprintf("%s %-9s %-34s %s", mark, r.label, r.value, r.fix)
}

// buildLine identifies the binary. A release build has all three of version,
// commit and date stamped in; a dev build says so rather than printing a version
// that no release ever carried.
func buildLine() string {
	parts := []string{"sshmgr " + version.Version, runtime.GOOS + "/" + runtime.GOARCH}
	switch {
	case version.Date != "" && version.Commit != "":
		parts = append(parts, "built "+shortDate(version.Date)+" from "+version.Commit)
	case version.Commit != "":
		parts = append(parts, "built from "+version.Commit)
	case version.IsDev():
		// Only say "dev build" when the version really is a placeholder. This
		// used to be the fallback for any build without a commit, which meant a
		// `go install` binary - a real, identifiable, published version -
		// introduced itself as a dev build.
		parts = append(parts, "dev build")
	}
	return strings.Join(parts, "   ")
}

// shortDate trims an RFC 3339 build stamp to its date. The clock time of a
// release build is noise in a header.
func shortDate(s string) string {
	if i := strings.Index(s, "T"); i > 0 {
		return s[:i]
	}
	return s
}

// bannerRows assembles the state block; see overview.Rows, which the web
// overview reads too.
func bannerRows(p paths.Paths, m *manifest.Manifest, now time.Time) []bannerRow {
	var rows []bannerRow
	for _, r := range overview.Rows(p, m, now) {
		rows = append(rows, bannerRow{label: r.Label, value: r.Value, fix: r.Fix})
	}
	return rows
}

// writeBanner renders the header block.
func writeBanner(w io.Writer, p paths.Paths, m *manifest.Manifest, now time.Time) {
	_, _ = fmt.Fprintf(w, "\n  %s\n\n", buildLine())
	for _, row := range bannerRows(p, m, now) {
		_, _ = fmt.Fprintln(w, row.String())
	}
	_, _ = fmt.Fprintln(w)
}
