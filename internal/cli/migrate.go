package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/migratesvc"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newMigrateCmd is the native migrate verb: move a legacy home to the standard one.
func newMigrateCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Move a legacy home to the standard location",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			res, err := migratesvc.Migrate(p, force, time.Now().Format("20060102-150405"))
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "if both the legacy and standard home exist, back up the current home and replace it")
	return cmd
}
