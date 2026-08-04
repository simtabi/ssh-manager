package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/editor"
	"github.com/simtabi/ssh-manager/internal/services/lifecycle"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// strPtrIf returns &val if the named flag was set, else nil.
func strPtrIf(cmd *cobra.Command, flag, val string) *string {
	if cmd.Flags().Changed(flag) {
		return &val
	}
	return nil
}

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Manage a profile (add/edit/delete)"}

	var shared bool
	var keyName string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			scope := "per_service"
			if shared {
				scope = "shared"
			}
			ed := editor.New(paths.Resolve(nil, "", ""))
			if err := ed.AddProfile(args[0], scope, strPtrIf(c, "key-name", keyName)); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "added profile %s. Run `sshmgr reconcile` to apply.\n", args[0])
			return nil
		},
	}
	add.Flags().BoolVar(&shared, "shared", false, "key_scope=shared (one key per profile)")
	add.Flags().StringVar(&keyName, "key-name", "", "profile key name (shared scope)")
	cmd.AddCommand(add)

	var editScope, editKeyName string
	edit := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ed := editor.New(paths.Resolve(nil, "", ""))
			if err := ed.EditProfile(args[0], strPtrIf(c, "key-scope", editScope), strPtrIf(c, "key-name", editKeyName)); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "edited profile %s. Run `sshmgr reconcile` to apply.\n", args[0])
			return nil
		},
	}
	edit.Flags().StringVar(&editScope, "key-scope", "", "per_service | shared")
	edit.Flags().StringVar(&editKeyName, "key-name", "", "")
	cmd.AddCommand(edit)

	var yes, revoke, purge, noKeyBackup bool
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a profile, its config blocks and its host pins",
		Long: "Delete a profile, its config blocks and its host pins.\n\n" +
			"The manifest, the inventory records, the rendered Host blocks and any\n" +
			"known_hosts pin no surviving host still needs all go in one step. Key\n" +
			"files stay on disk unless --purge, which deletes them after writing an\n" +
			"encrypted backup.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			question := fmt.Sprintf("Delete profile %q and all its hosts?", name)
			if purge {
				question = fmt.Sprintf("Delete profile %q, all its hosts AND its key files on disk?", name)
			}
			if !yes && !confirm(c, question) {
				os.Exit(1)
			}
			doRevoke := revoke
			if !yes {
				doRevoke = confirm(c, "Revoke deployed public keys from their targets first?")
			}
			p := paths.Resolve(nil, "", "")
			out := c.OutOrStdout()
			if purge {
				if err := backupKeysBeforeDestroying(p, out, noKeyBackup); err != nil {
					return err
				}
			}
			snapshotBeforeMutation(p)
			res, err := lifecycle.New(p, runtime.GOOS == "darwin").
				DeleteProfile(name, lifecycle.Options{Purge: purge, Revoke: doRevoke})
			if err != nil {
				return err
			}
			fmt.Fprintln(out, res.Format())
			return nil
		},
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompts")
	del.Flags().BoolVar(&revoke, "revoke", false, "also revoke deployed keys from targets (with --yes)")
	del.Flags().BoolVar(&purge, "purge", false, "also delete the profile's key files and directory")
	del.Flags().BoolVar(&noKeyBackup, "no-key-backup", false,
		"purge without writing an encrypted backup first (the keys are then unrecoverable)")
	cmd.AddCommand(del)

	return cmd
}
