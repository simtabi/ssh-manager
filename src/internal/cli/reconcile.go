package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// newReconcileCmd is the native reconcile verb: apply the manifest to ~/.ssh
// (rebuild config, mint missing keys, fix perms) under the mutation guard, then
// auto-pin reachable hosts' known_hosts.
func newReconcileCmd() *cobra.Command {
	var dryRun, noPin, passphrase, yes bool
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Build ~/.ssh from the manifest",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			r := reconciler.New(p, m, inv, platform.EmitUseKeychain())
			out := c.OutOrStdout()

			if dryRun {
				res, err := r.Reconcile(true, "")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(out, res.Format())
				return nil
			}

			// Show the dry run as the confirmation. The user sees exactly what is
			// about to happen rather than being asked to agree to a verb name.
			preview, err := r.Reconcile(true, "")
			if err != nil {
				return err
			}
			if err := confirmChange(c, preview.Format(), yes); err != nil {
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
			snap := snapshotBeforeMutation(p)
			res, err := r.Reconcile(false, pw)
			if err != nil {
				return err
			}
			if snap != "" {
				res.Snapshot = &snap
			}
			if !noPin {
				res.Pinned = knownhosts.New(p.SSHDir).AutoPin(m, nil, os.Getenv)
			}
			_, _ = fmt.Fprintln(out, res.Format())
			// Reconcile is the command that leaves the tree in its intended state,
			// so it is where a key that will never be used should be noticed -
			// rather than at the next doctor run, days later.
			warnDangling(out, p, m)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without writing")
	cmd.Flags().BoolVar(&noPin, "no-pin", false, "don't auto-pin reachable hosts' known_hosts")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect newly minted keys (prompts without echo)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "apply without confirming (implied when there is no terminal)")
	return cmd
}

// readPassphrase collects the passphrase to protect newly minted keys. On a
// terminal it is read without echo and confirmed, so it never reaches the screen
// or the scrollback; when stdin is piped a single line is read so scripted use
// still works.
//
// The piped branch reads the command's own input rather than os.Stdin, so a
// caller that redirects input is honoured - without which this path could only
// ever be exercised by a real pipe.
func readPassphrase(in io.Reader) (string, error) {
	if !platform.StdinIsTerminal() {
		return platform.ReadLine(in)
	}
	first, err := platform.ReadSecret("passphrase for new keys: ")
	if err != nil {
		return "", err
	}
	again, err := platform.ReadSecret("confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", errors.New("passphrases did not match")
	}
	return first, nil
}
