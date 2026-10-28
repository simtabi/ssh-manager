package cli

import (
	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/cleaner"
)

// newCleanCmd sweeps what deleting things leaves behind: trust-store pins for
// hosts the manifest no longer has, and interrupted-write residue.
//
// Only lines sshmgr wrote (or was explicitly asked to adopt) are ever removed.
// A pin the user made by hand is left alone, because a trust store is not
// sshmgr's to tidy - and a pin for a host any profile still resolves survives
// too, since pruning is reference counted rather than owned.
func newCleanCmd() *cobra.Command {
	var dryRun, adopt, yes bool
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Remove stale known_hosts pins, stale records and write residue",
		Long: "Remove stale known_hosts pins, stale inventory records and write residue.\n\n" +
			"--adopt first tags the untagged pins that match a manifest host, putting\n" +
			"them under sshmgr's management so they are pruned when their host goes\n" +
			"away. It is opt-in: an untagged pin is presumed to be yours.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			// The question shows nothing read from the home, so asking first and
			// locking after it loses nothing - and no one's reading time holds
			// up other commands.
			if !dryRun {
				if err := confirmChange(c,
					"clean removes known_hosts pins tagged sshmgr that no host needs, "+
						"stale inventory records, and write residue.\nRun with --dry-run first to see what.", yes); err != nil {
					return err
				}
			}
			lockForMutation(p)
			return cleaner.Run(p, c.OutOrStdout(), adopt, dryRun, func() { snapshotBeforeMutation(p) })
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change, touch nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "clean without confirming (implied when there is no terminal)")
	cmd.Flags().BoolVar(&adopt, "adopt", false, "put untagged pins matching a manifest host under sshmgr's management")
	return cmd
}
