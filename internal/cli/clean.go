package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/paths"
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
			p := paths.Resolve(nil, "", "")
			if !dryRun {
				if err := confirmChange(c,
					"clean removes known_hosts pins tagged sshmgr that no host needs, "+
						"stale inventory records, and write residue.\nRun with --dry-run first to see what.", yes); err != nil {
					return err
				}
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			kh := knownhosts.New(p.SSHDir)

			// Stale inventory records are the one dangling state safe to fix
			// without asking: a record is a JSON entry pointing at a key nothing
			// owns any more, so removing it destroys no key material. Every other
			// state involves a file, and those are for the user to decide about -
			// clean reports them and stops.
			audit, err := keyaudit.New(m, inv, p.SSHDir).Audit(false)
			if err != nil {
				return err
			}
			stale := audit.ByState(keyaudit.StaleInventory)

			// Report from the same classifier the mutation uses, so what a
			// --dry-run promises is what a real run does.
			var adoptable []knownhosts.Entry
			if adopt {
				if adoptable, err = kh.AdoptCandidates(m); err != nil {
					return err
				}
			}
			prunable, err := kh.PruneCandidates(m)
			if err != nil {
				return err
			}

			if dryRun {
				report(out, "would adopt", adoptable)
				report(out, "would prune", prunable)
				reportRecords(out, "would drop", stale)
				residue := snapshots.FindTempArtifacts(p.SSHDir)
				for _, r := range residue {
					_, _ = fmt.Fprintf(out, "would remove residue: %s\n", r)
				}
				if len(adoptable)+len(prunable)+len(stale)+len(residue) == 0 {
					_, _ = fmt.Fprintln(out, "nothing to clean")
				}
				reportRemaining(out, audit)
				return nil
			}

			snapshotBeforeMutation(p) // also sweeps the write residue
			if adopt {
				n, err := kh.Adopt(m)
				if err != nil {
					return err
				}
				report(out, fmt.Sprintf("adopted %d", n), adoptable)
			}
			// Re-scan after adopting: a line adopted a moment ago is tagged now,
			// and a freshly tagged line still matches a live host, so this can only
			// ever prune what the first scan already found.
			n, err := kh.Prune(m)
			if err != nil {
				return err
			}
			report(out, fmt.Sprintf("pruned %d", n), prunable)
			if len(stale) > 0 {
				for _, f := range stale {
					delete(inv.Keys, f.Subject)
				}
				if err := inv.Save(p.Inventory()); err != nil {
					return err
				}
				reportRecords(out, fmt.Sprintf("dropped %d", len(stale)), stale)
			}
			if n == 0 && len(stale) == 0 && (!adopt || len(adoptable) == 0) {
				_, _ = fmt.Fprintln(out, "nothing to clean")
			}
			reportRemaining(out, audit)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change, touch nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "clean without confirming (implied when there is no terminal)")
	cmd.Flags().BoolVar(&adopt, "adopt", false, "put untagged pins matching a manifest host under sshmgr's management")
	return cmd
}

// reportRecords lists the inventory records clean is dropping. They are named by
// fingerprint, because that is what the inventory is keyed by and the path they
// pointed at no longer exists.
func reportRecords(out io.Writer, label string, findings []keyaudit.Finding) {
	if len(findings) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "%s stale inventory record(s):\n", label)
	for _, f := range findings {
		_, _ = fmt.Fprintf(out, "  %s  %s\n", f.Subject, f.Detail)
	}
}

// reportRemaining names what clean deliberately will not touch. Everything left
// involves a key file, and deleting one is the user's call - but leaving it
// unmentioned is how a dangling key survives a command called "clean".
func reportRemaining(out io.Writer, audit keyaudit.Report) {
	var rest []keyaudit.Finding
	for _, f := range audit.Findings {
		if f.State != keyaudit.StaleInventory {
			rest = append(rest, f)
		}
	}
	if len(rest) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "\n%d dangling key(s) left alone (they involve key files; see `sshmgr doctor`):\n", len(rest))
	for _, f := range rest {
		_, _ = fmt.Fprintf(out, "  %s  %s\n", f.State, f.Subject)
	}
}

func report(out io.Writer, label string, entries []knownhosts.Entry) {
	if len(entries) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "%s known_hosts line(s):\n", label)
	for _, e := range entries {
		_, _ = fmt.Fprintf(out, "  %s  %s  %s\n", e.Name(), e.Keytype, e.Fingerprint)
	}
}
