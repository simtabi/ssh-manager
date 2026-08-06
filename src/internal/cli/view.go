package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/query"
)

// newViewCmd is the native view verb: resolved config + key + deployment status
// for a profile or host alias.
func newViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view <profile|alias>",
		Short: "Resolved host config + key + deployment status",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			d, err := query.New(m, inv, p.Providers()).Detail(args[0])
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			switch v := d.(type) {
			case *query.ProfileSummary:
				renderProfileSummary(out, v)
			case *query.HostDetail:
				renderHostDetail(out, v)
			}
			return nil
		},
	}
}

func renderProfileSummary(out io.Writer, s *query.ProfileSummary) {
	_, _ = fmt.Fprintf(out, "profile %s  (key_scope: %s)\n", s.Name, s.KeyScope)
	for _, r := range s.Rows {
		_, _ = fmt.Fprintf(out, "  %s  %s  [%s]  %s  (%s)\n", r.Alias, r.Hostname, r.ProviderLabel, r.KeyName, r.Status)
	}
}

func renderHostDetail(out io.Writer, d *query.HostDetail) {
	_, _ = fmt.Fprintf(out, "%s  (profile %s)\n", d.Alias, d.Profile)
	row := func(k, v string) { _, _ = fmt.Fprintf(out, "  %-13s %s\n", k+":", v) }
	row("hostname", d.Hostname)
	row("user", d.User)
	row("port", fmt.Sprintf("%d", d.Port))
	row("provider", d.ProviderLabel)
	row("key", d.KeyName)
	row("identity", d.IdentityFile)
	row("known_hosts", d.KnownHosts)
	row("status", d.Status)
	if d.Fingerprint != nil {
		row("fingerprint", *d.Fingerprint)
	}
	if d.ExpiresOn != nil {
		row("expires_on", *d.ExpiresOn)
	}
	if len(d.Tags) > 0 {
		row("tags", strings.Join(d.Tags, ", "))
	}
	if d.RequiresVPN {
		v := "yes"
		if d.VPNName != nil {
			v = *d.VPNName
		}
		if d.VPNURL != nil {
			v += " (" + *d.VPNURL + ")"
		}
		row("requires_vpn", v)
	}
	if d.RawOptions.Len() > 0 {
		_, _ = fmt.Fprintln(out, "  options:")
		for _, k := range d.RawOptions.Keys() {
			_, _ = fmt.Fprintf(out, "    %s %s\n", k, d.RawOptions.Get(k))
		}
	}
	if len(d.Deployments) > 0 {
		_, _ = fmt.Fprintln(out, "  deployments:")
		for _, dep := range d.Deployments {
			flag := "unverified"
			if dep.Verified {
				flag = "verified"
			}
			_, _ = fmt.Fprintf(out, "    - %s via %s (%s)\n", dep.Target, dep.Method, flag)
		}
	}
}
