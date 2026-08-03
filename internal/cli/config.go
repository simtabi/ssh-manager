package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// loadConfigService resolves the home, loads the manifest, and builds the config
// service. emitUseKeychain matches the platform (macOS only), as in v1.
func loadConfigService() (paths.Paths, *manifest.Manifest, *configsvc.Service, error) {
	p := paths.Resolve(nil, "", "")
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		return paths.Paths{}, nil, nil, err
	}
	return p, m, configsvc.New(p.SSHDir, m, runtime.GOOS == "darwin"), nil
}

// migrateLegacyKnownHosts merges any known_hosts left over under profiles/*/
// from before the trust store consolidated into one file, then deletes them.
// One-shot and idempotent: a tree with none is a no-op, so render can call this
// unconditionally every time rather than requiring a separate migration step.
func migrateLegacyKnownHosts(c *cobra.Command, p paths.Paths, dryRun bool) error {
	legacy, _ := filepath.Glob(filepath.Join(p.SSHDir, "profiles", "*", "known_hosts"))
	if len(legacy) == 0 {
		return nil
	}
	if dryRun {
		fmt.Fprintf(c.OutOrStdout(), "would migrate: %d legacy known_hosts file(s) into the single store\n", len(legacy))
		return nil
	}
	snapshotBeforeMutation(p)
	rep, err := knownhosts.New(p.SSHDir).MigrateLegacyStores()
	if err != nil {
		return err
	}
	if len(rep.Removed) > 0 {
		fmt.Fprintf(c.OutOrStdout(), "migrated %d known_hosts line(s) from %s into the single store\n",
			rep.Merged, strings.Join(rep.Removed, ", "))
	}
	return nil
}

// newConfigCmd is the first verb group running natively in Go (no engine).
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Render, check, or show the SSH config",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Verify the config matches the manifest (read-only; exit non-zero on drift)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			_, _, svc, err := loadConfigService()
			if err != nil {
				return err
			}
			res, err := svc.Check(true)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			if !res.InSync() {
				os.Exit(1)
			}
			return nil
		},
	})

	var dryRun bool
	render := &cobra.Command{
		Use:   "render",
		Short: "Render the config files from the manifest",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, _, svc, err := loadConfigService()
			if err != nil {
				return err
			}
			if err := migrateLegacyKnownHosts(c, p, dryRun); err != nil {
				return err
			}
			res, err := svc.Write(dryRun)
			if err != nil {
				return err
			}
			verb := "wrote"
			if dryRun {
				verb = "would write"
			}
			out := c.OutOrStdout()
			if len(res.Written) > 0 {
				fmt.Fprintf(out, "%s: %s\n", verb, strings.Join(res.Written, ", "))
			}
			if len(res.Pruned) > 0 {
				fmt.Fprintf(out, "pruned: %s\n", strings.Join(res.Pruned, ", "))
			}
			if len(res.Written) == 0 && len(res.Pruned) == 0 {
				fmt.Fprintln(out, "config: already in sync")
			}
			return nil
		},
	}
	render.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "preview changes without writing")
	cmd.AddCommand(render)

	cmd.AddCommand(&cobra.Command{
		Use:   "show [alias]",
		Short: "Print the rendered config, or ssh -G for one alias",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			_, _, svc, err := loadConfigService()
			if err != nil {
				return err
			}
			alias := ""
			if len(args) > 0 {
				alias = args[0]
			}
			out, err := svc.Show(alias)
			fmt.Fprint(c.OutOrStdout(), out)
			return err
		},
	})

	return cmd
}
