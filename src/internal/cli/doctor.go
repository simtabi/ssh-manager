package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/doctor"
)

// newDoctorCmd is the native (engine-free) doctor verb: diagnose deps, perms,
// agent, known_hosts, and manifest-vs-disk drift/hygiene. Exits non-zero when the
// report is not clean, matching v1.
func newDoctorCmd() *cobra.Command {
	var fix, jsonOut, strict bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose deps, perms, agent, known_hosts, drift, dangling keys",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			// A missing/invalid manifest is non-fatal: drift checks are skipped.
			m, _ := manifest.Load(p.Manifest())
			svc := doctor.New(p, m, platform.EmitUseKeychain())

			out := c.OutOrStdout()
			if fix {
				for _, change := range svc.FixPerms() {
					if !jsonOut {
						_, _ = fmt.Fprintln(out, "fixed perms:", change)
					}
				}
			}
			rep := svc.Run(strict)
			if jsonOut {
				b, err := rep.JSON()
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(out, string(b))
			} else {
				_, _ = fmt.Fprintln(out, rep.Format())
			}
			if !rep.OK() {
				return errNotClean
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "auto-fix perms first")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output (scripting)")
	cmd.Flags().BoolVar(&strict, "strict", false,
		"treat every dangling-key state as a failure, not only the blocking ones (for CI)")
	return cmd
}
