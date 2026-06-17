package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/doctor"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newDoctorCmd is the native (engine-free) doctor verb: diagnose deps, perms,
// agent, known_hosts, and manifest-vs-disk drift/hygiene. Exits non-zero when the
// report is not clean, matching v1.
func newDoctorCmd() *cobra.Command {
	var fix, jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose deps, perms, agent, known_hosts, drift",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			// A missing/invalid manifest is non-fatal: drift checks are skipped.
			m, _ := manifest.Load(p.Manifest())
			svc := doctor.New(p, m, runtime.GOOS == "darwin")

			out := c.OutOrStdout()
			if fix {
				for _, change := range svc.FixPerms() {
					if !jsonOut {
						fmt.Fprintln(out, "fixed perms:", change)
					}
				}
			}
			rep := svc.Run()
			if jsonOut {
				b, err := rep.JSON()
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(b))
			} else {
				fmt.Fprintln(out, rep.Format())
			}
			if !rep.OK() {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "auto-fix perms first")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output (scripting)")
	return cmd
}
