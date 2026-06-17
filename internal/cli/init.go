package cli

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/initsvc"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newInitCmd is the native init verb: create/converge the per-user home.
func newInitCmd() *cobra.Command {
	var force, backup bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create/converge the per-user home",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			stamp := ""
			if force && backup {
				stamp = time.Now().Format("20060102-150405")
			}
			res, err := initsvc.New(p, runtime.GOOS == "darwin").Run(force, backup, stamp)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite manifest/inventory/.env with fresh defaults")
	cmd.Flags().BoolVar(&backup, "backup", false, "with --force, copy the old files into <home>/.state/ before overwriting")
	return cmd
}
