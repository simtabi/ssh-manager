package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
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
	var dryRun, adopt bool
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Remove stale known_hosts pins and write residue",
		Long: "Remove stale known_hosts pins and write residue.\n\n" +
			"--adopt first tags the untagged pins that match a manifest host, putting\n" +
			"them under sshmgr's management so they are pruned when their host goes\n" +
			"away. It is opt-in: an untagged pin is presumed to be yours.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			kh := knownhosts.New(p.SSHDir)

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
				residue := snapshots.FindTempArtifacts(p.SSHDir)
				for _, r := range residue {
					fmt.Fprintf(out, "would remove residue: %s\n", r)
				}
				if len(adoptable)+len(prunable)+len(residue) == 0 {
					fmt.Fprintln(out, "nothing to clean")
				}
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
			if n == 0 && (!adopt || len(adoptable) == 0) {
				fmt.Fprintln(out, "nothing to clean")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change, touch nothing")
	cmd.Flags().BoolVar(&adopt, "adopt", false, "put untagged pins matching a manifest host under sshmgr's management")
	return cmd
}

func report(out io.Writer, label string, entries []knownhosts.Entry) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(out, "%s known_hosts line(s):\n", label)
	for _, e := range entries {
		fmt.Fprintf(out, "  %s  %s  %s\n", e.Name(), e.Keytype, e.Fingerprint)
	}
}
