package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/platform"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/lock"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// heldLock keeps the acquired advisory lock alive for the rest of the process so
// the OS doesn't release it (and GC doesn't close the fd) before the mutation
// finishes; a short-lived CLI command releases it on exit.
var heldLock func()

// snapshotBeforeMutation is the native mutation guard (mirrors the Facade's
// _mutating): take the advisory lock so concurrent commands serialize, sweep crash
// residue, then snapshot ~/.ssh so the change is reversible. The lock is best-
// effort - a failure to acquire doesn't block the operation. Returns the snapshot
// path ("" if none was made).
//
// The lock is taken once per process, not once per call. flock is per open file
// descriptor, and Acquire blocks until it is free, so a second call in the same
// process waits forever on a lock that same process is holding - a deadlock with
// no output at all. One CLI command mutates once and exits, which is why this
// went unnoticed; the TUI is one process that mutates repeatedly (reconcile,
// then pin, then rotate) and hangs on the second action. Nothing is given up by
// holding it: the lock exists to serialize separate processes, and within one
// process these run in sequence anyway.
func snapshotBeforeMutation(p paths.Paths) string {
	if heldLock == nil {
		rel, err := lock.Acquire(p.LockFile())
		if err != nil {
			// Best-effort stays best-effort - refusing to work because a lock file
			// cannot be made would strand the user on a read-only or exotic
			// filesystem - but not silent. Acquire blocks while another process
			// holds the lock, so an error here means the lock itself is broken,
			// and the serialization the guard promises is simply not happening.
			_, _ = fmt.Fprintf(os.Stderr, "sshmgr: WARNING: could not take the advisory lock at %s, "+
				"so a concurrent sshmgr command could interleave with this one: %v\n", p.LockFile(), err)
		} else {
			heldLock = rel
		}
	}
	snapshots.CleanTempArtifacts(p.SSHDir)
	snap, _ := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), snapshotRetain(), "")
	return snap
}

// applyManifestEdit re-renders ~/.ssh/config after a command changed the
// manifest, and reports what moved.
//
// The rendered config is a pure function of the manifest, so every manifest edit
// makes the file on disk stale - which is exactly the drift `doctor` and `diff`
// exist to report. Leaving that to a later reconcile meant a successful edit
// ended with the tool complaining about a problem it had just created, and the
// user being told to run a second command to finish the first. So the rule is:
// a command that changes the manifest renders; a command that only touches key
// files (keygen, rotate) changes no manifest state and does not.
//
// This is safe to run after any edit. Rendering replaces the managed block and
// preserves everything around it (renderer.ComposeRootConfig), so it never
// disturbs hand-written config, and it is idempotent - an edit that changes no
// Host block writes nothing and says nothing.
func applyManifestEdit(c *cobra.Command, p paths.Paths) error {
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		return err
	}
	// A manifest can exist before ~/.ssh does (config home and ssh dir are
	// separate); the root config is written without creating its parent.
	if err := fs.EnsureDir(p.SSHDir, perms.DirMode); err != nil {
		return err
	}
	res, err := configsvc.New(p.SSHDir, m, platform.EmitUseKeychain()).Write(false)
	if err != nil {
		return fmt.Errorf("the manifest edit was saved, but the config could not be re-rendered "+
			"(fix this, then run `sshmgr reconcile`): %w", err)
	}
	out := c.OutOrStdout()
	if len(res.Written) > 0 {
		_, _ = fmt.Fprintf(c.OutOrStdout(), "re-rendered %s\n", strings.Join(res.Written, ", "))
	}
	if len(res.Pruned) > 0 {
		_, _ = fmt.Fprintf(out, "removed stale %s\n", strings.Join(res.Pruned, ", "))
	}
	return nil
}

// warnDangling reports the blocking dangling-key states inline, right after the
// command that could have caused one.
//
// Only the blocking ones, and only after the command's own output: a key nothing
// will ever use is worth interrupting for, while an unminted key or a stale
// record is doctor's business. Failing to audit is silent - this is a courtesy
// on the end of a command that already succeeded, not a check in its own right.
func warnDangling(out io.Writer, p paths.Paths, m *manifest.Manifest) {
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		return
	}
	rep, err := keyaudit.New(m, inv, p.SSHDir).Audit(false)
	if err != nil || rep.OK() {
		return
	}
	_, _ = fmt.Fprintln(out)
	for _, f := range rep.Findings {
		if !keyaudit.Blocking(f.State) {
			continue
		}
		_, _ = fmt.Fprintf(out, "WARNING: %s is %s - %s\n", f.Subject, f.State, f.Detail)
		if f.Fix != "" {
			_, _ = fmt.Fprintf(out, "  -> %s\n", f.Fix)
		}
	}
}
