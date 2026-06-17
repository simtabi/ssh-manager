// Package cli is the cobra command surface for ssh-manager. The command name
// stays "sshmgr" (the v1 console script); the verb set mirrors v1's cli.py.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/version"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sshmgr",
		Short:         "Profile-based SSH key & config lifecycle manager",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newConfigCmd())     // native Go (first verb off the engine)
	root.AddCommand(newValidateCmd())   // native Go
	root.AddCommand(newDoctorCmd())     // native Go
	root.AddCommand(newProvidersCmd())  // native Go
	root.AddCommand(newNetCmd())        // native Go
	root.AddCommand(newSnapshotsCmd())  // native Go
	root.AddCommand(newKnownHostsCmd()) // native Go
	root.AddCommand(newReconcileCmd())  // native Go
	addPassthroughCommands(root)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ssh-manager version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "sshmgr %s\n", version.Version)
			return nil
		},
	}
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "sshmgr:", err)
		os.Exit(1)
	}
}
