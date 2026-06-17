package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/notifier"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newAuditCmd is the native audit verb: deployment + expiry + hygiene summary plus
// recent activity. --notify also fires the cadence-gated desktop alert.
func newAuditCmd() *cobra.Command {
	var notify bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Deployment, expiry, and hygiene report",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			now := time.Now()
			var lines []string

			lines = append(lines, "=== deployments ===")
			if len(inv.Keys) == 0 {
				lines = append(lines, "  (inventory empty - run reconcile, then deploy)")
			}
			for _, fp := range sortedByPath(inv) {
				rec := inv.Keys[fp]
				status := "deployed"
				if rec.NeedsRedeploy() {
					status = "needs-redeploy"
				}
				lines = append(lines, fmt.Sprintf("%s  [%s]", rec.Path, status))
				lines = append(lines, "    "+fp)
				for _, d := range rec.Deployments {
					flag := "unverified"
					if d.Verified {
						flag = "verified"
					}
					date := ""
					if d.Date != nil {
						date = *d.Date
					}
					lines = append(lines, strings.TrimRight(fmt.Sprintf("    - %s via %s (%s) %s", d.Target, d.Method, flag, date), " "))
				}
			}

			lines = append(lines, "", "=== expiry ===")
			states, err := notifier.New(p, m.Defaults).States(now)
			if err != nil {
				return err
			}
			if len(states) == 0 {
				lines = append(lines, "  (nothing tracked)")
			}
			for _, s := range states {
				days := "?"
				if s.DaysRemaining != nil {
					days = fmt.Sprintf("%dd", *s.DaysRemaining)
				}
				expires := "?"
				if s.ExpiresOn != nil {
					expires = *s.ExpiresOn
				}
				lines = append(lines, fmt.Sprintf("  %s  %s  (%s, %s)", s.KeyName, s.State, expires, days))
			}

			lines = append(lines, "", "=== recent activity ===")
			if recent := recentAudit(p.AuditLog(), 10); len(recent) > 0 {
				lines = append(lines, recent...)
			} else {
				lines = append(lines, "  (no audit log yet)")
			}

			if notify {
				fired := notifier.New(p, m.Defaults).Notify(now, false)
				status := "not sent (not due, disabled, or no notifier backend)"
				if fired {
					status = "sent"
				}
				lines = append(lines, "", "desktop notification: "+status)
			}
			fmt.Fprintln(c.OutOrStdout(), strings.Join(lines, "\n"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&notify, "notify", false, "also fire the cadence-gated desktop alert")
	return cmd
}

// sortedByPath returns inventory fingerprints ordered by (path, fingerprint) for
// stable output (a Go map has no insertion order to mirror Python's).
func sortedByPath(inv *inventory.Inventory) []string {
	fps := make([]string, 0, len(inv.Keys))
	for fp := range inv.Keys {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool {
		pi, pj := inv.Keys[fps[i]].Path, inv.Keys[fps[j]].Path
		if pi != pj {
			return pi < pj
		}
		return fps[i] < fps[j]
	})
	return fps
}

func recentAudit(path string, n int) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		return nil
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]string, len(all))
	for i, ln := range all {
		out[i] = "  " + ln
	}
	return out
}
