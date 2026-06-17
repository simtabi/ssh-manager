package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/agent"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newLoadCmd is the native load verb: add a profile's keys to the ssh-agent
// (macOS keychain).
func newLoadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "load <profile>",
		Short: "Add a profile's keys to the agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			profile := args[0]
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if _, ok := m.Profiles[profile]; !ok {
				return fmt.Errorf("unknown profile: %q", profile)
			}
			a := agent.New(runtime.GOOS == "darwin")
			added, err := agent.Load(m, p.SSHDir, profile, a.Add)
			if err != nil {
				return err
			}
			names := "(none)"
			if len(added) > 0 {
				names = strings.Join(added, ", ")
			}
			fmt.Fprintf(c.OutOrStdout(), "loaded %d key(s) into the agent: %s\n", len(added), names)
			return nil
		},
	}
}
