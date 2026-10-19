package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/rotator"
)

func newRotateCmd() *cobra.Command {
	var allowUnverified, passphrase, yes, noKeyBackup, all, dryRun bool
	var category string
	cmd := &cobra.Command{
		Use:   "rotate [<[profile/]key>|profile|alias ...] [--category <name>] [--all]",
		Short: "Zero-downtime staged key rotation",
		Long: "Zero-downtime staged key rotation.\n\n" +
			"The key being replaced is archived to the profile's old/ dir, but only one\n" +
			"predecessor is kept - so rotating again discards the one before it for good.\n" +
			"An encrypted bundle is written first unless --no-key-backup is given.\n\n" +
			"Name one key, several, whole profiles or host aliases, every key in a\n" +
			"category, or --all. Each key rotates on its own: one that fails is left\n" +
			"untouched and the rest still rotate. A key no host uses is skipped, since\n" +
			"there is nothing to deploy it to.",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 1 && !all && category == "" && !dryRun {
				return rotateOne(c, args[0], allowUnverified, passphrase, yes, noKeyBackup)
			}
			return rotateMany(c, keysvc.Selection{Selectors: args, Category: category, All: all},
				allowUnverified, passphrase, yes, noKeyBackup, dryRun)
		},
	}
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified", false, "commit even if a target can't auto-verify")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect the rotated-in key (prompts without echo)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&noKeyBackup, "no-key-backup", false,
		"rotate without writing an encrypted backup first (the earlier predecessor is lost)")
	cmd.Flags().BoolVar(&all, "all", false, "rotate every key a host uses")
	cmd.Flags().StringVar(&category, "category", "", "rotate every key in profiles of this category")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "list the keys that would rotate, and change nothing")
	return cmd
}

// rotateOne is the single-key rotation, unchanged from before batches existed.
func rotateOne(c *cobra.Command, key string, allowUnverified, passphrase, yes, noKeyBackup bool) error {
	if err := confirmOrAbort(c, fmt.Sprintf("Rotate %s? (the current key moves to old/, "+
		"replacing any earlier predecessor)", key), yes); err != nil {
		return err
	}
	p, err := resolvePaths(c)
	if err != nil {
		return err
	}
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
}

// rotateMany rotates a selection of keys one after another: one confirmation,
// one backup, one snapshot, and the inventory saved after every committed key
// so an interrupted batch keeps what it finished.
func rotateMany(c *cobra.Command, sel keysvc.Selection, allowUnverified, passphrase, yes, noKeyBackup, dryRun bool) error {
	out := c.OutOrStdout()
	p, err := resolvePaths(c)
	if err != nil {
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
	rows, err := keysvc.New(m, inv, p.SSHDir).Select(sel)
	if err != nil {
		return err
	}
	var todo []keysvc.Row
	for _, r := range rows {
		if !r.Wired() {
			_, _ = fmt.Fprintf(out, "skip     %s - no host uses it, so there is nothing to rotate it on\n", r.Ref)
			continue
		}
		todo = append(todo, r)
	}
	if len(todo) == 0 {
		_, _ = fmt.Fprintln(out, "nothing to rotate")
		return nil
	}
	names := make([]string, len(todo))
	for i, r := range todo {
		names[i] = r.Ref.String()
	}
	if dryRun {
		for _, n := range names {
			_, _ = fmt.Fprintln(out, "rotate   "+n)
		}
		_, _ = fmt.Fprintf(out, "(dry run) %d key(s) would rotate\n", len(names))
		return nil
	}
	if err := confirmOrAbort(c, fmt.Sprintf("Rotate %d key(s): %s? (each current key moves to old/, "+
		"replacing any earlier predecessor)", len(names), strings.Join(names, ", ")), yes); err != nil {
		return err
	}
	if err := backupKeysBeforeDestroying(p, out, noKeyBackup); err != nil {
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
	rot := rotator.New(p, m, inv)
	var failed []string
	for _, n := range names {
		report, err := rot.Rotate(n, allowUnverified, pw)
		switch {
		case err != nil:
			failed = append(failed, n)
			_, _ = fmt.Fprintf(out, "rotation FAILED: %s\n  %v\n", n, err)
			continue
		case report.Committed:
			if err := inv.Save(p.Inventory()); err != nil {
				return err
			}
		default:
			failed = append(failed, n)
		}
		_, _ = fmt.Fprintln(out, report.Format())
	}
	_, _ = fmt.Fprintf(out, "%d of %d key(s) rotated", len(names)-len(failed), len(names))
	if len(failed) > 0 {
		_, _ = fmt.Fprintf(out, "; not rotated (left as they were): %s\n", strings.Join(failed, ", "))
		return errNotClean
	}
	_, _ = fmt.Fprintln(out)
	return nil
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
			p, err := resolvePaths(c)
			if err != nil {
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
