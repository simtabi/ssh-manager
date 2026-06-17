package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/rotator"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func newRotateCmd() *cobra.Command {
	var allowUnverified, passphrase, yes bool
	cmd := &cobra.Command{
		Use:   "rotate <key>",
		Short: "Zero-downtime staged key rotation",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			if !yes && !confirm(c, fmt.Sprintf("Rotate %s? (~/.ssh is snapshotted first)", key)) {
				os.Exit(1)
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			pw := ""
			if passphrase {
				pw = readPassphrase(c)
			}
			snapshotBeforeMutation(p)
			report, err := rotator.New(p, m, inv).Rotate(key, allowUnverified, pw)
			if err != nil {
				return err
			}
			if report.Committed {
				if err := inv.Save(p.Inventory()); err != nil {
					return err
				}
			}
			fmt.Fprintln(c.OutOrStdout(), report.Format())
			if !report.Committed {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified", false, "commit even if a target can't auto-verify")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect the rotated-in key (prompts on stdin)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

func newRollbackCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rollback <key>",
		Short: "Restore the previous key",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			if !yes && !confirm(c, fmt.Sprintf("Roll back %s to its /old/ predecessor?", key)) {
				os.Exit(1)
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			snapshotBeforeMutation(p)
			report, err := rotator.New(p, m, inv).Rollback(key)
			if err != nil {
				return err
			}
			if err := inv.Save(p.Inventory()); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), report.Format())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}
