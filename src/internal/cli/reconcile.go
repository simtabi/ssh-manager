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
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			if dryRun {
				lockForMutation(p)
				r, _, err := loadReconciler(p)
				if err != nil {
					return err
				}
				res, err := r.Reconcile(true, "")
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(c.OutOrStdout(), res.Format())
				return nil
			}

			return reconcileApply(c, p, yes, passphrase, noPin)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without writing")
	cmd.Flags().BoolVar(&noPin, "no-pin", false, "don't auto-pin reachable hosts' known_hosts")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect newly minted keys (prompts without echo)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "apply without confirming (implied when there is no terminal)")
	return cmd
}

// loadReconciler reads the manifest and inventory a reconcile works from.
func loadReconciler(p paths.Paths) (*reconciler.Reconciler, *manifest.Manifest, error) {
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		return nil, nil, err
	}
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		return nil, nil, err
	}
	return reconciler.New(p, m, inv, platform.EmitUseKeychain()), m, nil
}

// reconcileApply is reconcile's applying half - preview as confirmation, then
// snapshot, mint, pin and warn - shared with `host apply --reconcile`. It asks
// before it takes the lock and checks the preview again under it (see
// recheck); asking nobody, it locks first. host apply --reconcile calls it with
// the lock already held, which makes the lock a no-op and the check a formality.
func reconcileApply(c *cobra.Command, p paths.Paths, yes, passphrase, noPin bool) error {
	out := c.OutOrStdout()
	willAsk := asks(yes)
	if !willAsk {
		lockForMutation(p)
	}
	r, m, err := loadReconciler(p)
	if err != nil {
		return err
	}
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
	if willAsk {
		shown := preview.Format()
		if err := recheck(p, shown, func() (string, error) {
			if r, m, err = loadReconciler(p); err != nil {
				return "", err
			}
			again, err := r.Reconcile(true, "")
			if err != nil {
				return "", err
			}
			return again.Format(), nil
		}); err != nil {
			return err
		}
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
	warnDangling(out, p, m)
	return nil
}

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
