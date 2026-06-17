package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/validate"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newValidateCmd is the native (engine-free) validate verb. It checks that each
// managed keypair parses, the public matches the private, and perms are correct;
// it exits non-zero if any key fails, matching v1.
func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [selector]",
		Short: "Check keypairs parse, match, and have safe perms",
		Long: "Validate managed keypairs: each key parses, the public matches the " +
			"private, and perms are correct. selector filters by key name or profile; " +
			"omit it to validate every managed key. Exits non-zero if any key fails.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			selector := ""
			if len(args) > 0 {
				selector = args[0]
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			checks, err := validate.New(m, p.SSHDir).ValidateKeys(selector)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(checks) == 0 {
				fmt.Fprintln(out, "no managed keys to validate")
				return nil
			}
			failed := 0
			for _, ch := range checks {
				status := "OK  "
				if !ch.OK {
					status = "FAIL"
					failed++
				}
				fp := ""
				if ch.Fingerprint != nil {
					fp = "  " + *ch.Fingerprint
				}
				fmt.Fprintf(out, "%s  %s [%s]%s\n", status, ch.KeyName, ch.Profile, fp)
				for _, issue := range ch.Issues {
					fmt.Fprintf(out, "        - %s\n", issue)
				}
				for _, note := range ch.Notes {
					fmt.Fprintf(out, "        (%s)\n", note)
				}
			}
			fmt.Fprintf(out, "\n%d key(s) checked, %d failed\n", len(checks), failed)
			if failed > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
}
