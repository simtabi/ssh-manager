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
	var force, yes bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Move a legacy home to the standard location",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			if err := confirmChange(c,
				"migrate moves a legacy home into "+p.ConfigDir+
					"; with --force the current home is backed up aside and replaced.", yes); err != nil {
				return err
			}
			res, err := migratesvc.Migrate(p, force, time.Now().Format("20060102-150405"))
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "if both the legacy and standard home exist, back up the current home and replace it")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "migrate without confirming (implied when there is no terminal)")
	return cmd
}
