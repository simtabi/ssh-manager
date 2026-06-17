package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/providers"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// newProvidersCmd is the native providers verb: list the configured provider
// catalog with live credential presence, or --export the shipped default to the
// home for editing.
func newProvidersCmd() *cobra.Command {
	var export, force bool
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List the active provider catalog + credential state",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			out := c.OutOrStdout()
			if export {
				dest := p.Providers()
				if fs.Exists(dest) && !force {
					return fmt.Errorf("%s already exists - use --force to overwrite it", dest)
				}
				if err := fs.EnsureDir(p.ConfigDir, perms.DirMode); err != nil {
					return err
				}
				if err := fs.WriteTextAtomic(dest, string(providers.DefaultCatalog()), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote provider catalog to %s - edit it to customize "+
					"(delete it to track the shipped default again)\n", dest)
				return nil
			}
			infos := providers.List(p.Providers(), os.Getenv)
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROVIDER\tCATEGORY\tKIND\tTOKEN ENV\tCREDENTIAL")
			for _, i := range infos {
				tokenEnv := i.TokenEnv
				if tokenEnv == "" {
					tokenEnv = "-"
				}
				cred := "n/a"
				if i.TokenEnv != "" {
					cred = "missing"
					if i.TokenPresent {
						cred = "present"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Name, i.Category, i.Kind, tokenEnv, cred)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&export, "export", false, "write the default catalog to <home>/providers.json to customize")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file (with --export)")
	return cmd
}
