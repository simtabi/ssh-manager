package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/deployer"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newDeployCmd is the native deploy verb: install a key's public half on its
// target(s) via the provider adapter (named adapter -> generic ssh -> manual) and
// record it. Exits non-zero if any attempted deploy failed.
func newDeployCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "deploy <[profile/]key> [target]",
		Short: "Install a public key on its target",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			target := ""
			if len(args) > 1 {
				target = args[1]
			}
			p := paths.Resolve(nil, "", "")
			if err := confirmChange(c,
				"deploy installs the public half of "+key+" on its target.", yes); err != nil {
				return err
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			// Deploy writes the inventory and installs a key on a remote target, so
			// it takes the same guard every other mutating verb does. Without it two
			// concurrent deploys - a scheduled `audit --notify` and a manual run,
			// say - could interleave their inventory writes, and there was no
			// snapshot to go back to.
			snapshotBeforeMutation(p)
			report, err := deployer.New(p, m, inv).Deploy(key, target)
			if err != nil {
				return err
			}
			if err := inv.Save(p.Inventory()); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(c.OutOrStdout(), report.Format())
			// A failed automated deploy / unreachable host is non-zero; a manual
			// target that still needs a paste is not (exit 0).
			if report.AnyError() {
				return errNotClean
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "deploy without confirming (implied when there is no terminal)")
	return cmd
}
