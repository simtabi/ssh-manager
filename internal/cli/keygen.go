package cli

import (
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

// newKeygenCmd is the native keygen verb: targeted key generation for a profile or
// host alias. Missing keys are minted; existing keys are warned about and skipped
// unless --force (which prompts per key; ~/.ssh is snapshotted first).
func newKeygenCmd() *cobra.Command {
	var force, noPin, passphrase, yes bool
	cmd := &cobra.Command{
		Use:   "keygen <profile|alias>",
		Short: "Generate a profile's or host's keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			target := args[0]
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if !selectorKnown(m, target) {
				return fmt.Errorf("unknown profile or host: %q", target)
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			r := reconciler.New(p, m, inv, runtime.GOOS == "darwin")
			out := c.OutOrStdout()

			existing, err := r.ExistingKeys(target)
			if err != nil {
				return err
			}
			overwrite := map[string]bool{}
			if len(existing) > 0 {
				fmt.Fprintf(out, "%d key(s) already exist in %q: %s\n", len(existing), target, strings.Join(existing, ", "))
				if !force {
					fmt.Fprintln(out, "  existing keys will be SKIPPED - re-run with --force to "+
						"overwrite (a ~/.ssh snapshot is taken first; undo via `sshmgr snapshots restore`).")
				} else {
					for _, name := range existing {
						if yes || confirm(c, fmt.Sprintf("  overwrite %s? (~/.ssh is snapshotted first)", name)) {
							overwrite[name] = true
						}
					}
				}
			}

			pw := ""
			if passphrase {
				pw = readPassphrase(c)
			}
			snapshotBeforeMutation(p)
			minted, err := r.Mint(target, pw, overwrite)
			if err != nil {
				return err
			}
			if !noPin && len(minted) > 0 {
				profs := map[string]bool{}
				for _, mk := range minted {
					profs[mk.Profile] = true
				}
				knownhosts.New(p.SSHDir).AutoPin(m, profs, os.Getenv)
			}
			if len(minted) == 0 {
				fmt.Fprintf(out, "no keys minted for %q (all present; --force to overwrite)\n", target)
				return nil
			}
			for _, mk := range minted {
				fmt.Fprintf(out, "minted %s  %s  (needs-redeploy)\n", mk.KeyName, mk.Fingerprint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing keys (prompts; ~/.ssh snapshotted first)")
	cmd.Flags().BoolVar(&noPin, "no-pin", false, "don't auto-pin reachable hosts' known_hosts")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect newly minted keys (prompts on stdin)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "answer yes to overwrite prompts")
	return cmd
}

// selectorKnown reports whether selector names a profile or a host alias.
func selectorKnown(m *manifest.Manifest, selector string) bool {
	if _, ok := m.Profiles[selector]; ok {
		return true
	}
	for _, prof := range m.Profiles {
		for _, h := range prof.Hosts {
			if h.Alias == selector {
				return true
			}
		}
	}
	return false
}
