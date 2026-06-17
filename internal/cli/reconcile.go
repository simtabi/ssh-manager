package cli

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newReconcileCmd is the native reconcile verb: apply the manifest to ~/.ssh
// (rebuild config, mint missing keys, fix perms) under the mutation guard, then
// auto-pin reachable hosts' known_hosts.
func newReconcileCmd() *cobra.Command {
	var dryRun, noPin, passphrase bool
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
			r := reconciler.New(p, m, inv, runtime.GOOS == "darwin")
			out := c.OutOrStdout()

			if dryRun {
				res, err := r.Reconcile(true, "")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, res.Format())
				return nil
			}

			pw := ""
			if passphrase {
				pw = readPassphrase(c)
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
			fmt.Fprintln(out, res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without writing")
	cmd.Flags().BoolVar(&noPin, "no-pin", false, "don't auto-pin reachable hosts' known_hosts")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect newly minted keys (prompts on stdin)")
	return cmd
}

// readPassphrase reads one line from stdin (echoed; for scripted/piped use).
func readPassphrase(c *cobra.Command) string {
	fmt.Fprint(c.OutOrStdout(), "passphrase for new keys: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
