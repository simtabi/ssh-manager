package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// loadConfigService resolves the home, loads the manifest, and builds the config
// service. emitUseKeychain matches the platform (macOS only), as in v1.
func loadConfigService() (*configsvc.Service, error) {
	p := paths.Resolve(nil, "", "")
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		return nil, err
	}
	return configsvc.New(p.SSHDir, m, runtime.GOOS == "darwin"), nil
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
			svc, err := loadConfigService()
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
			svc, err := loadConfigService()
			if err != nil {
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
			svc, err := loadConfigService()
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
