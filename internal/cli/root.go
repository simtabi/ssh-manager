// Package cli is the cobra command surface for ssh-manager. The command name
// stays "sshmgr" (the v1 console script); the verb set mirrors v1's cli.py and is
// now entirely native Go - there is no longer a Python engine behind any verb.
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
	root.AddCommand(newKeygenCmd())     // native Go
	root.AddCommand(newLoadCmd())       // native Go
	root.AddCommand(newDiffCmd())       // native Go
	root.AddCommand(newProfileCmd())    // native Go
	root.AddCommand(newHostCmd())       // native Go
	root.AddCommand(newInitCmd())       // native Go
	root.AddCommand(newImportCmd())     // native Go
	root.AddCommand(newMigrateCmd())    // native Go
	root.AddCommand(newRecoverCmd())    // native Go
	root.AddCommand(newBundleCmd())     // native Go
	root.AddCommand(newRestoreCmd())    // native Go
	root.AddCommand(newDeployCmd())     // native Go
	root.AddCommand(newRotateCmd())     // native Go
	root.AddCommand(newRollbackCmd())   // native Go
	root.AddCommand(newListCmd())       // native Go
	root.AddCommand(newViewCmd())       // native Go
	root.AddCommand(newExpiryCmd())     // native Go
	root.AddCommand(newAuditCmd())      // native Go
	root.AddCommand(newNotifyCmd())     // native Go
	root.AddCommand(newTuiCmd())        // native Go
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
