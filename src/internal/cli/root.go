// Package cli is the cobra command surface for ssh-manager. The command name
// stays "sshmgr", the one v1 installed as its console script, because a rename
// would have broken every script and ssh config that invokes it.
//
// The verb set is pinned against the implementation it replaced by
// TestTheCommandSurfaceMatchesTheOneItReplaced, which is what makes "no verb
// was lost" a checked claim rather than a recollection.
package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/version"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sshmgr",
		Short:         "Profile-based SSH key & config lifecycle manager",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          rootArgs,
		// Bare `sshmgr` on a terminal opens the menu; `sshmgr <verb>` is the CLI.
		// Someone who runs the binary by double-clicking it, or by typing its name
		// to see what it does, gets something they can use rather than a wall of
		// help - and a script still gets the CLI, because a script has no terminal.
		//
		// Piped or redirected input falls back to help: a TUI reading from a pipe
		// would consume whatever is there as menu answers, which is how a
		// non-interactive run ends up picking a menu item nobody chose.
		RunE: func(c *cobra.Command, _ []string) error {
			if !platform.StdinIsTerminal() {
				return c.Help()
			}
			return runTUI(c)
		},
	}
	// A sandbox root for the whole run: --dev-root ./scratch puts the ssh dir and
	// the config home under it and touches nothing in $HOME. Persistent, because
	// it has to apply to every verb - a flag that only some commands honoured
	// would produce a run that reads the sandbox and writes the real tree.
	root.SetFlagErrorFunc(unknownCommandBeforeFlags)
	root.PersistentFlags().String(devRootFlag, "",
		"run against a sandbox directory instead of ~/.ssh (also $"+paths.DevRootEnv+")")

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
	root.AddCommand(newKeyCmd())        // native Go
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
	root.AddCommand(newShowCmd())       // native Go
	root.AddCommand(newCleanCmd())      // native Go
	root.AddCommand(newExpiryCmd())     // native Go
	root.AddCommand(newAuditCmd())      // native Go
	root.AddCommand(newNotifyCmd())     // native Go
	root.AddCommand(newTuiCmd())        // native Go
	root.AddCommand(newGitCmd())        // native Go
	root.AddCommand(newVMCmd())         // native Go
	root.AddCommand(newTermiusCmd())    // native Go
	root.AddCommand(newHistoryCmd())    // native Go
	recordCommands(root)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ssh-manager version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "sshmgr %s\n", version.Version)
			return nil
		},
	}
}

// unknownCommandBeforeFlags reports a word that is not a command ahead of a
// flag error. The root takes no arguments, so `sshmgr nosuchcmd --open` is
// parsed as the root's own flags first, and cobra's "unknown flag: --open"
// hides the real problem: this build has no such command (an older binary
// on PATH, typically). A flag error on any real command is left as it is.
func unknownCommandBeforeFlags(c *cobra.Command, err error) error {
	if c.HasParent() || c.Flags().NArg() == 0 {
		return err
	}
	return unknownCommand(c, c.Flags().Arg(0))
}

// rootArgs refuses any word given to the root, as cobra.NoArgs did, but says
// which commands it may have meant: NoArgs reports an unknown command with no
// suggestion, so `sshmgr termus` never pointed at `termius`.
func rootArgs(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return unknownCommand(c, args[0])
}

func unknownCommand(c *cobra.Command, word string) error {
	msg := fmt.Sprintf("unknown command %q for %q", word, c.Name())
	if c.SuggestionsMinimumDistance <= 0 {
		c.SuggestionsMinimumDistance = 2
	}
	if s := c.SuggestionsFor(word); len(s) > 0 {
		msg += "\n\nDid you mean this?\n\t" + strings.Join(s, "\n\t")
	}
	return errors.New(msg + "\n\nRun 'sshmgr --help' for the commands this build has (sshmgr version names it).")
}
