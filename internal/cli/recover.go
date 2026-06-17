package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/recover"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newRecoverCmd is the native recover verb: print a break-glass recovery script.
func newRecoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recover [key]",
		Short: "Break-glass recovery snippet / fixkeys tool",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			keyName := ""
			if len(args) > 0 {
				keyName = args[0]
			}
			p := paths.Resolve(nil, "", "")
			// The manifest is only needed for a per-key snippet; tolerate its
			// absence when emitting the full fixkeys tool.
			m, _ := manifest.Load(p.Manifest())
			script, err := recover.Script(p, m, keyName)
			if err != nil {
				return err
			}
			fmt.Fprint(c.OutOrStdout(), script)
			return nil
		},
	}
}
