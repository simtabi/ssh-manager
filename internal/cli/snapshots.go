package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

const defaultSnapshotRetain = 10

// snapshotRetain is how many ~/.ssh snapshots to keep. $SSH_MANAGER_SNAPSHOT_RETAIN
// overrides it - the variable was documented but never actually read. A value of 0
// or less is rejected rather than honoured, since "keep none" would silently
// disable the rollback safety net for every subsequent command.
func snapshotRetain() int {
	raw := os.Getenv("SSH_MANAGER_SNAPSHOT_RETAIN")
	if raw == "" {
		return defaultSnapshotRetain
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 {
		return defaultSnapshotRetain
	}
	return n
}

// newSnapshotsCmd is the native snapshots verb group: list/restore/prune the local
// ~/.ssh backups.
func newSnapshotsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshots",
		Short: "List/restore/prune local ~/.ssh backups",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List local ~/.ssh snapshots (oldest -> newest)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			snaps := snapshots.List(p.SnapshotsDir())
			out := c.OutOrStdout()
			if len(snaps) == 0 {
				_, _ = fmt.Fprintln(out, "no snapshots yet")
				return nil
			}
			legacy := 0
			for _, s := range snaps {
				size := int64(0)
				if fi, err := os.Stat(s); err == nil {
					size = fi.Size()
				}
				note := ""
				if snapshots.HoldsKeyMaterial(s) {
					note = "\tholds private keys"
					legacy++
				}
				_, _ = fmt.Fprintf(out, "%s\t%8d bytes%s\n", filepath.Base(s), size, note)
			}
			// Snapshots written by older versions archived the whole tree. They are
			// not deleted automatically - they may be the only copy of something -
			// but the user should know what is sitting there.
			if legacy > 0 {
				_, _ = fmt.Fprintf(out, "\n%d snapshot(s) predate key exclusion and contain unencrypted private keys.\n"+
					"Remove them once you no longer need them: sshmgr snapshots prune --keep 0\n", legacy)
			}
			return nil
		},
	})

	var yes bool
	restore := &cobra.Command{
		Use:   "restore [snapshot]",
		Short: "Restore ~/.ssh config from a snapshot (private keys are left as they are)",
		Long: "Restore ~/.ssh config from a snapshot.\n\n" +
			"Snapshots hold config, known_hosts and public keys - never private keys, since\n" +
			"they are plaintext archives taken on every mutating command. Restoring puts those\n" +
			"files back and leaves everything else on disk untouched, so a key minted after the\n" +
			"snapshot survives the rollback. Use `sshmgr bundle` for encrypted key backups.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := confirmOrAbort(c, "Restore ~/.ssh config from a snapshot? (private keys are left as they are)", yes); err != nil {
				return err
			}
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			p := paths.Resolve(nil, "", "")
			chosen, err := snapshots.RestoreByID(p.SSHDir, p.SnapshotsDir(), snapshotRetain(), id)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "restored from %s\n", filepath.Base(chosen))
			return nil
		},
	}
	restore.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.AddCommand(restore)

	var keep int
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Prune old snapshots, keeping the most recent N",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			removed := snapshots.Prune(p.SnapshotsDir(), keep)
			_, _ = fmt.Fprintf(c.OutOrStdout(), "pruned %d snapshot(s)\n", removed)
			return nil
		},
	}
	prune.Flags().IntVar(&keep, "keep", snapshotRetain(), "how many to retain")
	cmd.AddCommand(prune)

	return cmd
}

// confirm reads a y/N answer from stdin.
func confirm(c *cobra.Command, prompt string) bool {
	_, _ = fmt.Fprintf(c.OutOrStdout(), "%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
