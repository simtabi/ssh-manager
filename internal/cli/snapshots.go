package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

const snapshotRetain = 10

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
				fmt.Fprintln(out, "no snapshots yet")
				return nil
			}
			for _, s := range snaps {
				size := int64(0)
				if fi, err := os.Stat(s); err == nil {
					size = fi.Size()
				}
				fmt.Fprintf(out, "%s\t%8d bytes\n", filepath.Base(s), size)
			}
			return nil
		},
	})

	var yes bool
	restore := &cobra.Command{
		Use:   "restore [snapshot]",
		Short: "Restore ~/.ssh from a snapshot (snapshots the current tree first)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if !yes && !confirm(c, "Restore ~/.ssh from a snapshot? (current tree is snapshotted first)") {
				os.Exit(1)
			}
			id := ""
			if len(args) > 0 {
				id = args[0]
			}
			p := paths.Resolve(nil, "", "")
			chosen, err := snapshots.RestoreByID(p.SSHDir, p.SnapshotsDir(), snapshotRetain, id)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "restored from %s\n", filepath.Base(chosen))
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
			fmt.Fprintf(c.OutOrStdout(), "pruned %d snapshot(s)\n", removed)
			return nil
		},
	}
	prune.Flags().IntVar(&keep, "keep", snapshotRetain, "how many to retain")
	cmd.AddCommand(prune)

	return cmd
}

// confirm reads a y/N answer from stdin.
func confirm(c *cobra.Command, prompt string) bool {
	fmt.Fprintf(c.OutOrStdout(), "%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
