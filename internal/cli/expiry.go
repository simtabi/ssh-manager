package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/notifier"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newExpiryCmd is the native expiry verb: per-key rotation-age table.
func newExpiryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "expiry",
		Short: "Per-key rotation-age table",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			states, err := notifier.New(p, m.Defaults).States(time.Now())
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(states) == 0 {
				fmt.Fprintln(out, "no keys tracked (run reconcile, then deploy)")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tSTATE\tEXPIRES\tDAYS LEFT")
			for _, s := range states {
				expires := "?"
				if s.ExpiresOn != nil {
					expires = *s.ExpiresOn
				}
				days := "?"
				if s.DaysRemaining != nil {
					days = fmt.Sprintf("%d", *s.DaysRemaining)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.KeyName, s.State, expires, days)
			}
			return tw.Flush()
		},
	}
}
