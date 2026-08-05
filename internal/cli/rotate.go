package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/rotator"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func newRotateCmd() *cobra.Command {
	var allowUnverified, passphrase, yes, noKeyBackup bool
	cmd := &cobra.Command{
		Use:   "rotate <[profile/]key>",
		Short: "Zero-downtime staged key rotation",
		Long: "Zero-downtime staged key rotation.\n\n" +
			"The key being replaced is archived to the profile's old/ dir, but only one\n" +
			"predecessor is kept - so rotating again discards the one before it for good.\n" +
			"An encrypted bundle is written first unless --no-key-backup is given.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			if err := confirmOrAbort(c, fmt.Sprintf("Rotate %s? (the current key moves to old/, "+
				"replacing any earlier predecessor)", key), yes); err != nil {
				return err
			}
			p := paths.Resolve(nil, "", "")
			if err := backupKeysBeforeDestroying(p, c.OutOrStdout(), noKeyBackup); err != nil {
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
			pw := ""
			if passphrase {
				secret, err := readPassphrase(c.InOrStdin())
				if err != nil {
					return err
				}
				pw = secret
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
			_, _ = fmt.Fprintln(c.OutOrStdout(), report.Format())
			if !report.Committed {
				return errNotClean
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified", false, "commit even if a target can't auto-verify")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect the rotated-in key (prompts without echo)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&noKeyBackup, "no-key-backup", false,
		"rotate without writing an encrypted backup first (the earlier predecessor is lost)")
	return cmd
}

func newRollbackCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rollback <[profile/]key>",
		Short: "Restore the previous key",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			if err := confirmOrAbort(c, fmt.Sprintf("Roll back %s to its /old/ predecessor?", key), yes); err != nil {
				return err
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
			_, _ = fmt.Fprintln(c.OutOrStdout(), report.Format())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}
