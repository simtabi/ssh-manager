package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// snapshotBeforeMutation is the mutation guard: lock, sweep crash residue,
// snapshot ~/.ssh. It lives in services/mutation, so the web can guard its
// changes the same way; this keeps the CLI's call sites unchanged.
func snapshotBeforeMutation(p paths.Paths) string {
	return mutation.SnapshotBeforeMutation(p, snapshotRetain())
}

// lockForMutation takes the advisory lock, once per process, before a command
// reads the state it is about to change. See mutation.LockForMutation.
func lockForMutation(p paths.Paths) {
	mutation.LockForMutation(p)
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
