package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// newDiffCmd is the native diff verb: preview the manifest vs. on-disk reality -
// config drift plus which keys the manifest wants that aren't on disk yet.
func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Preview manifest vs. on-disk reality",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			svc := configsvc.New(p.SSHDir, m, platform.EmitUseKeychain())
			chk, err := svc.Check(true)
			if err != nil {
				return err
			}
			lines := []string{"=== config ===", chk.Format(), "", "=== keys ==="}
			rks, err := m.IterResolved()
			if err != nil {
				return err
			}
			var missing []string
			present := 0
			seen := map[manifest.KeyRef]bool{}
			for _, rk := range rks {
				ref := manifest.KeyRef{Profile: rk.Profile, KeyName: rk.KeyName}
				if seen[ref] {
					continue // hosts sharing one key are one key to mint
				}
				seen[ref] = true
				priv := filepath.Join(p.SSHDir, "profiles", ref.Profile, ref.KeyName)
				if fs.Exists(priv) {
					present++
				} else {
					missing = append(missing, fmt.Sprintf("  MINT  %s (manifest wants it; not on disk)", ref))
				}
			}
			lines = append(lines, missing...)
			lines = append(lines, fmt.Sprintf("  %d key(s) already present", present))
			_, _ = fmt.Fprintln(c.OutOrStdout(), strings.Join(lines, "\n"))
			return nil
		},
	}
}
