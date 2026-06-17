package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/importer"
	"github.com/simtabi/ssh-manager/internal/util/homeperms"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newImportCmd is the native import verb: onboard an existing ~/.ssh into the
// manifest + inventory. import REPLACES them wholesale (it does not merge), so a
// non-empty manifest is refused without --force (and both are backed up first).
func newImportCmd() *cobra.Command {
	var dryRun, force bool
	cmd := &cobra.Command{
		Use:   "import [path]",
		Short: "Onboard an existing ~/.ssh into the manifest",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			configPath := "~/.ssh/config"
			if len(args) > 0 {
				configPath = args[0]
			}
			p := paths.Resolve(nil, "", "")
			imp := importer.New(p, runtime.GOOS == "darwin")

			if dryRun {
				res, err := imp.Run(configPath, true)
				if err != nil {
					return err
				}
				fmt.Fprintln(c.OutOrStdout(), res.Format())
				return nil
			}

			// import replaces the manifest + inventory (config home, outside the
			// ~/.ssh snapshot). Refuse to clobber a non-empty manifest without --force.
			snapshotBeforeMutation(p)
			if m, err := manifest.Load(p.Manifest()); err == nil && len(m.Profiles) > 0 {
				if !force {
					return fmt.Errorf("a non-empty manifest already exists - importing replaces it " +
						"(it does not merge). Re-run with --force; the current manifest + " +
						"inventory are backed up to <home>/.state/ first.")
				}
				backupImportTargets(p)
			}
			res, err := imp.Run(configPath, false)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "parse and report without writing")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "replace an existing non-empty manifest (backed up first)")
	return cmd
}

// backupImportTargets copies manifest + inventory into <home>/.state/import-backup-<ts>/.
func backupImportTargets(p paths.Paths) {
	backup := filepath.Join(p.StateDir(), "import-backup-"+time.Now().Format("20060102-150405"))
	for _, src := range []string{p.Manifest(), p.Inventory()} {
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.MkdirAll(backup, homeperms.DirMode); err != nil {
			return
		}
		copyToBackup(src, filepath.Join(backup, filepath.Base(src)))
	}
}

func copyToBackup(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, homeperms.FileMode)
	if err != nil {
		return
	}
	_, _ = io.Copy(out, in)
	_ = out.Close()
}
