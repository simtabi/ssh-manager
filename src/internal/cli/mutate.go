package cli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
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
// manifest; see change.ApplyManifestEdit, which the web's changes call too.
func applyManifestEdit(c *cobra.Command, p paths.Paths) error {
	return change.ApplyManifestEdit(c.OutOrStdout(), p)
}

// warnDangling reports the blocking dangling-key states after a command that
// could have caused one; see change.WarnDangling.
func warnDangling(out io.Writer, p paths.Paths, m *manifest.Manifest) {
	change.WarnDangling(out, p, m)
}
