package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/editor"
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

	var yes, revoke bool
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a profile (prompts to revoke + prune)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if !yes && !confirm(c, fmt.Sprintf("Delete profile %q and all its hosts?", args[0])) {
				os.Exit(1)
			}
			doRevoke := revoke
			if !yes {
				doRevoke = confirm(c, "Revoke deployed public keys from their targets first?")
			}
			ed := editor.New(paths.Resolve(nil, "", ""))
			res, err := ed.DeleteProfile(args[0], doRevoke)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompts")
	del.Flags().BoolVar(&revoke, "revoke", false, "also revoke deployed keys from targets (with --yes)")
	cmd.AddCommand(del)

	return cmd
}
