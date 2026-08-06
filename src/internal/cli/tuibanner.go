package cli

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/doctor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/notifier"
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

// bannerRows assembles the state block. Every lookup is best-effort: a banner
// that fails to render because one probe errored would make the tool unusable
// for the exact person most likely to need it - someone whose ~/.ssh is broken.
func bannerRows(p paths.Paths, m *manifest.Manifest, now time.Time) []bannerRow {
	rep := doctor.New(p, m, platform.EmitUseKeychain()).Run(false)

	home := p.ConfigDir
	if rep.ProvidersSource != "" {
		home += "   (providers: " + rep.ProvidersSource + ")"
	}
	rows := []bannerRow{
		{label: "home", value: home},
		{label: "ssh", value: p.SSHDir},
	}

	// Counts, or the first-run state. "none yet" plus the command that creates
	// one is the whole of what a new user needs from this screen.
	if m == nil {
		rows = append(rows, bannerRow{label: "manifest", value: "none yet", fix: "sshmgr init"})
	} else {
		rows = append(rows, bannerRow{label: "manifest", value: manifestCounts(m)})
	}

	rows = append(rows, bannerRow{label: "agent", value: rep.AgentStatus})

	if m != nil {
		if rep.ConfigInSync {
			rows = append(rows, bannerRow{label: "rendered", value: "config in sync"})
		} else {
			rows = append(rows, bannerRow{
				label: "rendered", value: "drifted from the manifest", fix: "sshmgr reconcile"})
		}
		rows = append(rows, pinRow(rep, m))
	}

	if n := len(rep.PermIssues); n > 0 {
		rows = append(rows, bannerRow{
			label: "perms", value: fmt.Sprintf("%s with the wrong mode", plural(n, "path", "paths")),
			fix: "sshmgr doctor --fix"})
	}
	if !rep.Dangling.OK() {
		rows = append(rows, bannerRow{
			label: "keys", value: fmt.Sprintf("%s need attention", plural(len(rep.Dangling.Findings), "key", "keys")),
			fix: "sshmgr doctor"})
	}
	if !rep.Preflight.OK() {
		rows = append(rows, bannerRow{
			label: "deps", value: "a required OpenSSH tool is missing", fix: "sshmgr doctor"})
	}
	if rep.StrandedLegacyHome != "" {
		rows = append(rows, bannerRow{
			label: "legacy", value: "an old config home is still on disk", fix: "sshmgr migrate"})
	}

	// Expiry last: it is a schedule rather than a fault, and it is the one row
	// that is normally absent.
	if m != nil {
		if due := notifier.New(p, m).Banner(now); due != "" {
			rows = append(rows, bannerRow{
				label: "rotation", value: firstLine(due), fix: "sshmgr rotate"})
		}
	}
	return rows
}

// pinRow reports trust-store coverage as a fraction, because "6 of 7" says both
// how much is done and how much is left; a bare count of unpinned hosts reads as
// fine when it is 0 and as meaningless when it is 3.
func pinRow(rep doctor.Report, m *manifest.Manifest) bannerRow {
	total := hostCount(m)
	unpinned := len(rep.UnpinnedHosts)
	switch {
	case total == 0:
		return bannerRow{label: "pins", value: "no hosts declared"}
	case unpinned == 0:
		return bannerRow{label: "pins", value: fmt.Sprintf("all %d pinned", total)}
	default:
		return bannerRow{
			label: "pins",
			value: fmt.Sprintf("%d of %d pinned", total-unpinned, total),
			fix:   "sshmgr knownhosts pin",
		}
	}
}

func manifestCounts(m *manifest.Manifest) string {
	profiles := len(m.ProfileNames())
	keys := 0
	if refs, err := m.KeyRefs(); err == nil {
		keys = len(refs)
	}
	return fmt.Sprintf("%s, %s, %s",
		plural(profiles, "profile", "profiles"),
		plural(hostCount(m), "host", "hosts"),
		plural(keys, "key", "keys"))
}

func hostCount(m *manifest.Manifest) int {
	if m == nil {
		return 0
	}
	n := 0
	for _, name := range m.ProfileNames() {
		n += len(m.Profiles[name].Hosts)
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// writeBanner renders the header block.
func writeBanner(w io.Writer, p paths.Paths, m *manifest.Manifest, now time.Time) {
	_, _ = fmt.Fprintf(w, "\n  %s\n\n", buildLine())
	for _, row := range bannerRows(p, m, now) {
		_, _ = fmt.Fprintln(w, row.String())
	}
	_, _ = fmt.Fprintln(w)
}
