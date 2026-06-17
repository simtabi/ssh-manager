package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/query"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newListCmd is the native list verb: profiles -> hosts (tree), filterable.
func newListCmd() *cobra.Command {
	var profile, provider, typ, tag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Filterable tree across profiles",
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
			groups, err := query.New(m, inv, p.Providers()).Groups(profile, provider, typ, tag)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			filtered := profile != "" || provider != "" || typ != "" || tag != ""
			if len(groups) == 0 && filtered {
				fmt.Fprintln(out, "no hosts match the filter")
				return nil
			}
			for _, g := range groups {
				if g.Empty {
					fmt.Fprintf(out, "%s  (no hosts)\n", g.Name)
					continue
				}
				fmt.Fprintln(out, g.Name)
				for _, r := range g.Rows {
					tags := ""
					if len(r.Tags) > 0 {
						tags = "  #" + strings.Join(r.Tags, " #")
					}
					fmt.Fprintf(out, "  %s  %s  [%s]  %s  (%s)%s\n",
						r.Alias, r.Hostname, r.ProviderLabel, r.KeyName, r.Status, tags)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "filter to one profile")
	cmd.Flags().StringVar(&provider, "provider", "", "filter by provider")
	cmd.Flags().StringVar(&typ, "type", "", "provider category, e.g. vcs")
	cmd.Flags().StringVar(&tag, "tag", "", "filter by host tag")
	return cmd
}
