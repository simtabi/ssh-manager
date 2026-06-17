package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/netstat"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newNetCmd is the native net verb: per-host reachability with a VPN indicator.
// Exits non-zero when a VPN-required host is unreachable, matching v1.
func newNetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "net [selector]",
		Short: "Per-host connection status + VPN indicator",
		Args:  cobra.MaximumNArgs(1),
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
			rows, err := netstat.Status(m, selector)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			gatedDown := false
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Status.Icon(), r.Profile, r.Alias, r.Status.Message())
				if !r.Status.Reachable && r.Status.RequiresVPN {
					gatedDown = true
				}
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if gatedDown {
				os.Exit(1)
			}
			return nil
		},
	}
}
