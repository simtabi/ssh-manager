package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
)

// newKeygenCmd is the native keygen verb: targeted key generation for a profile or
// host alias. Missing keys are minted; existing keys are warned about and skipped
// unless --force, which prompts per key and moves each replaced key to old/.
func newKeygenCmd() *cobra.Command {
	var force, noPin, passphrase, yes, noKeyBackup bool
	cmd := &cobra.Command{
		Use:   "keygen <profile|alias>",
		Short: "Generate a profile's or host's keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			target := args[0]
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			// It asks about overwrites when --force is given without --yes, and
			// asks to proceed on a terminal. Either way it asks before it locks,
			// then re-reads under the lock (see recheck); asking nobody, it locks
			// first, as it always did.
			willAsk := !yes && (force || stdinIsTerminal())
			if !willAsk {
				lockForMutation(p)
			}
			var m *manifest.Manifest
			var r *reconciler.Reconciler
			var existing []manifest.KeyRef
			load := func() error {
				var err error
				if m, err = manifest.Load(p.Manifest()); err != nil {
					return err
				}
				if !selectorKnown(m, target) {
					return fmt.Errorf("unknown profile or host: %q", target)
				}
				inv, err := inventory.Load(p.Inventory())
				if err != nil {
					return err
				}
				r = reconciler.New(p, m, inv, platform.EmitUseKeychain())
				existing, err = r.ExistingKeys(target)
				return err
			}
			if err := load(); err != nil {
				return err
			}
			out := c.OutOrStdout()
			// Keyed by ref, and prompted per ref. The same key name legitimately
			// exists in several profiles, so both the question and the answer have
			// to name the profile - otherwise one "yes" regenerates a stranger's
			// identity in another profile.
			overwrite := map[manifest.KeyRef]bool{}
			if len(existing) > 0 {
				names := make([]string, 0, len(existing))
				for _, ref := range existing {
					names = append(names, ref.String())
				}
				_, _ = fmt.Fprintf(out, "%d key(s) already exist in %q: %s\n", len(existing), target, strings.Join(names, ", "))
				if !force {
					_, _ = fmt.Fprintln(out, "  existing keys will be SKIPPED - re-run with --force to "+
						"overwrite (the replaced key is kept in the profile's old/ dir).")
				} else {
					for _, ref := range existing {
						if yes || confirm(c, fmt.Sprintf("  overwrite %s? (the replaced key moves to old/)", ref)) {
							overwrite[ref] = true
						}
					}
				}
			}

			pw := ""
			if passphrase {
				secret, err := readPassphrase(c.InOrStdin())
				if err != nil {
					return err
				}
				pw = secret
			}
			// The overwrite prompts above cover replacing an existing key. This
			// covers minting a new one, which is still a change to ~/.ssh.
			if len(overwrite) == 0 {
				what := "keygen mints the missing keys for " + target + "."
				if target == "" {
					what = "keygen mints every missing key in the manifest."
				}
				if err := confirmChange(c, what, yes); err != nil {
					return err
				}
			}
			if willAsk {
				// The answers were about these keys existing; they still must.
				shown := keyRefs(existing)
				if err := recheck(p, shown, func() (string, error) {
					err := load()
					return keyRefs(existing), err
				}); err != nil {
					return err
				}
			}
			// Overwriting displaces the current key into old/, which discards any
			// predecessor already parked there. Backed up under the lock, so it is
			// of the keys about to be replaced, not of what another command left.
			if len(overwrite) > 0 {
				if err := backupKeysBeforeDestroying(p, out, noKeyBackup); err != nil {
					return err
				}
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
				_, _ = fmt.Fprintf(out, "no keys minted for %q (all present; --force to overwrite)\n", target)
				return nil
			}
			for _, mk := range minted {
				_, _ = fmt.Fprintf(out, "minted %s  %s  (needs-redeploy)\n", mk.KeyName, mk.Fingerprint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing keys (prompts; replaced keys move to old/)")
	cmd.Flags().BoolVar(&noPin, "no-pin", false, "don't auto-pin reachable hosts' known_hosts")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect newly minted keys (prompts without echo)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "answer yes to overwrite prompts")
	cmd.Flags().BoolVar(&noKeyBackup, "no-key-backup", false,
		"overwrite without writing an encrypted backup first (any earlier predecessor is lost)")
	return cmd
}

// selectorKnown reports whether selector names a profile, a host alias, or a key
// - the same set planMint filters on, so a target this accepts never plans zero
// keys and a target it rejects is genuinely unknown.
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
	refs, err := m.KeyRefs()
	if err != nil {
		return false
	}
	for _, ref := range refs {
		if selector == ref.KeyName || selector == ref.String() {
			return true
		}
	}
	return false
}

func keyRefs(refs []manifest.KeyRef) string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.String())
	}
	return strings.Join(names, ",")
}
