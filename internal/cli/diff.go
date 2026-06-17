package cli

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/paths"
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
			svc := configsvc.New(p.SSHDir, m, runtime.GOOS == "darwin")
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
			for _, rk := range rks {
				priv := filepath.Join(p.SSHDir, "profiles", rk.Profile, rk.KeyName)
				if fs.Exists(priv) {
					present++
				} else {
					missing = append(missing, fmt.Sprintf("  MINT  %s (manifest wants it; not on disk)", rk.KeyName))
				}
			}
			lines = append(lines, missing...)
			lines = append(lines, fmt.Sprintf("  %d key(s) already present", present))
			fmt.Fprintln(c.OutOrStdout(), strings.Join(lines, "\n"))
			return nil
		},
	}
}
