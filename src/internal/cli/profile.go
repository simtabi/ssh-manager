package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/lifecycle"
)

// keyCommentFlagHelp describes the key_comment template on profile add and edit.
const keyCommentFlagHelp = "comment template for keys minted from now on: {profile} {alias} {key} {date} {device} (default {profile}/{alias} {date})"

// sharedFlagHelp describes --shared, the shorthand profile add and edit share.
const sharedFlagHelp = "shorthand for --key-scope shared (--shared=false: per_service)"

// scopeFlags resolves --key-scope and its shorthand --shared into one value,
// "" when neither was given. Both may be given only when they agree, so a
// script that says --shared --key-scope per_service is told, not guessed at.
func scopeFlags(c *cobra.Command, scope string, shared bool) (string, error) {
	if !c.Flags().Changed("shared") {
		if c.Flags().Changed("key-scope") {
			return scope, nil
		}
		return "", nil
	}
	want := "per_service"
	if shared {
		want = "shared"
	}
	if c.Flags().Changed("key-scope") && scope != want {
		return "", fmt.Errorf("--shared=%t conflicts with --key-scope %s", shared, scope)
	}
	return want, nil
}

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
	var addScope, keyName, addCategory, addComment string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			scope, err := scopeFlags(c, addScope, shared)
			if err != nil {
				return err
			}
			if scope == "" {
				scope = "per_service"
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			lockForMutation(p)
			snapshotBeforeMutation(p)
			ed := editor.New(p)
			if err := ed.AddProfile(args[0], scope, strPtrIf(c, "key-name", keyName)); err != nil {
				return err
			}
			if addCategory != "" {
				if _, err := ed.SetCategory(args[0], addCategory); err != nil {
					return err
				}
			}
			if addComment != "" {
				if err := ed.SetKeyComment(args[0], addComment); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "added profile %s (no hosts yet - add one with "+
				"`sshmgr host add %s <alias>`)\n", args[0], args[0])
			return applyManifestEdit(c, p)
		},
	}
	add.Flags().StringVar(&addScope, "key-scope", "per_service", "per_service | shared (shared: one key, --key-name, for every host)")
	add.Flags().BoolVar(&shared, "shared", false, sharedFlagHelp)
	add.Flags().StringVar(&keyName, "key-name", "", "profile key name (shared scope)")
	add.Flags().StringVar(&addComment, "key-comment", "", keyCommentFlagHelp)
	add.Flags().StringVar(&addCategory, "category", "",
		"file the profile under profiles/<category>/ and render its hosts into profiles/<category>/config")
	cmd.AddCommand(add)

	var editShared bool
	var editScope, editKeyName, editCategory, editComment string
	edit := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			scope, err := scopeFlags(c, editScope, editShared)
			if err != nil {
				return err
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			lockForMutation(p)
			snapshotBeforeMutation(p)
			ed := editor.New(p)
			if c.Flags().Changed("category") {
				res, err := ed.SetCategory(args[0], editCategory)
				if err != nil {
					return err
				}
				if res.From != res.To {
					verb := "keys expected at"
					if res.Moved {
						verb = "moved keys to"
					}
					_, _ = fmt.Fprintf(c.OutOrStdout(), "%s: %s %s (was %s); %d inventory record(s) updated\n",
						args[0], verb, res.To, res.From, res.RecordsUpdated)
				}
			}
			if c.Flags().Changed("key-comment") {
				if err := ed.SetKeyComment(args[0], editComment); err != nil {
					return err
				}
			}
			var scopePtr *string
			if scope != "" {
				scopePtr = &scope
			}
			if scopePtr != nil || c.Flags().Changed("key-name") ||
				!c.Flags().Changed("category") && !c.Flags().Changed("key-comment") {
				if err := ed.EditProfile(args[0], scopePtr, strPtrIf(c, "key-name", editKeyName)); err != nil {
					return err
				}
			}
			// Changing key_scope or key_name changes which key each host resolves
			// to, and that key may not exist yet.
			_, _ = fmt.Fprintf(c.OutOrStdout(), "edited profile %s (run `sshmgr reconcile` to mint any key "+
				"this now points at)\n", args[0])
			if err := applyManifestEdit(c, p); err != nil {
				return err
			}
			// Switching key_scope or key_name re-points every host in the profile,
			// stranding whatever they used to name.
			if m, err := manifest.Load(p.Manifest()); err == nil {
				warnDangling(c.OutOrStdout(), p, m)
			}
			return nil
		},
	}
	edit.Flags().StringVar(&editScope, "key-scope", "", "per_service | shared")
	edit.Flags().BoolVar(&editShared, "shared", false, sharedFlagHelp)
	edit.Flags().StringVar(&editKeyName, "key-name", "", "the shared key every host in this profile uses (key_scope: shared)")
	edit.Flags().StringVar(&editComment, "key-comment", "", keyCommentFlagHelp+"; \"\" inherits defaults.key_comment")
	edit.Flags().StringVar(&editCategory, "category", "",
		"move the profile under profiles/<category>/ (its key directory and inventory records follow); \"\" returns it to the flat layout")
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
			if err := confirmOrAbort(c, question, yes); err != nil {
				return err
			}
			doRevoke := revoke
			if !yes {
				doRevoke = confirm(c, "Revoke deployed public keys from their targets first?")
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			lockForMutation(p)
			out := c.OutOrStdout()
			if purge {
				if err := backupKeysBeforeDestroying(p, out, noKeyBackup); err != nil {
					return err
				}
			}
			snapshotBeforeMutation(p)
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).
				DeleteProfile(name, lifecycle.Options{Purge: purge, Revoke: doRevoke})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, res.Format())
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
