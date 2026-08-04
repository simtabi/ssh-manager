package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/platform"
	"github.com/simtabi/ssh-manager/internal/services/editor"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/internal/services/lifecycle"
	"github.com/simtabi/ssh-manager/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// newKeyCmd is the key lifecycle verb. A key used to exist only as a property of
// a host; these subcommands manage it in its own right - declare and mint one,
// see what state every key is in, and take one away.
func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Manage a profile's keys (add/list/delete)"}
	cmd.AddCommand(newKeyAddCmd())
	cmd.AddCommand(newKeyListCmd())
	cmd.AddCommand(newKeyDeleteCmd())
	return cmd
}

func newKeyDeleteCmd() *cobra.Command {
	var purge, revoke, yes, noKeyBackup bool
	cmd := &cobra.Command{
		Use:   "delete <profile/key>",
		Short: "Delete a key (refuses while a host uses it)",
		Long: "Delete a key (refuses while a host uses it).\n\n" +
			"Without --purge the manifest declaration and the inventory record go away\n" +
			"and the key files stay on disk, so an accidental delete costs nothing.\n" +
			"--purge deletes the files too, after writing an encrypted backup.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			ref, err := m.ResolveKeySelector(args[0])
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			what := fmt.Sprintf("Delete key %s?", ref)
			if purge {
				what = fmt.Sprintf("Delete key %s AND its files on disk?", ref)
			}
			if !yes && !confirm(c, what) {
				os.Exit(1)
			}
			if purge {
				if err := backupKeysBeforeDestroying(p, out, noKeyBackup); err != nil {
					return err
				}
			}
			snapshotBeforeMutation(p)
			res, err := lifecycle.New(p, platform.EmitUseKeychain()).
				DeleteKey(ref, lifecycle.Options{Purge: purge, Revoke: revoke})
			if err != nil {
				return err
			}
			fmt.Fprintln(out, res.Format())
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete the key files from disk")
	cmd.Flags().BoolVar(&revoke, "revoke", false, "revoke the deployed public key from its targets first")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&noKeyBackup, "no-key-backup", false,
		"purge without writing an encrypted backup first (the key is then unrecoverable)")
	return cmd
}

func newKeyAddCmd() *cobra.Command {
	var host, keyType string
	var rotateAfterDays int
	var passphrase bool
	cmd := &cobra.Command{
		Use:   "add <profile> <name>",
		Short: "Declare a key on a profile and mint it",
		Long: "Declare a key on a profile and mint it.\n\n" +
			"--host wires the key to an existing host in the same profile, which is\n" +
			"what makes it a rendered IdentityFile. Without it the key is minted but\n" +
			"UNWIRED: it exists on disk and nothing uses it.",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			profile, name := args[0], args[1]
			p := paths.Resolve(nil, "", "")
			out := c.OutOrStdout()

			// Prompt before mutating anything, so an abandoned prompt leaves the
			// manifest untouched.
			pw := ""
			if passphrase {
				secret, err := readPassphrase()
				if err != nil {
					return err
				}
				pw = secret
			}

			snapshotBeforeMutation(p)
			ed := editor.New(p)
			if err := ed.AddKey(profile, name,
				strPtrIf(c, "type", keyType), intPtrIf(c, "rotate-after-days", rotateAfterDays),
				host); err != nil {
				return err
			}

			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			ref := manifest.KeyRef{Profile: profile, KeyName: name}
			minted, err := reconciler.New(p, m, inv, platform.EmitUseKeychain()).MintRef(ref, pw)
			if err != nil {
				return err
			}
			switch {
			case minted != nil:
				fmt.Fprintf(out, "minted %s  %s  (needs-redeploy)\n", ref, minted.Fingerprint)
			default:
				fmt.Fprintf(out, "declared %s (a key already exists at that path; left untouched)\n", ref)
			}
			if host != "" {
				fmt.Fprintf(out, "wired to host %s\n", host)
			} else {
				fmt.Fprintf(out, "UNWIRED: no host uses %s yet. Wire it with:\n"+
					"  sshmgr host edit %s <alias> --key-name %s\n", ref, profile, name)
			}
			return applyManifestEdit(c, p)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "wire an existing host in this profile to the key")
	cmd.Flags().StringVar(&keyType, "type", "", "key algorithm (default: the manifest's defaults.key_type)")
	cmd.Flags().IntVar(&rotateAfterDays, "rotate-after-days", 0,
		"rotation interval for this key (default: the manifest's defaults.rotate_after_days)")
	cmd.Flags().BoolVar(&passphrase, "passphrase", false, "protect the new key (prompts without echo)")
	return cmd
}

func newKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [profile|alias|key]",
		Short: "Every key with its fingerprint, expiry, hosts and state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			selector := ""
			if len(args) > 0 {
				selector = args[0]
			}
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return err
			}
			rows, err := keysvc.New(m, inv, p.SSHDir).Rows(selector)
			if err != nil {
				return err
			}
			writeKeyTable(c.OutOrStdout(), rows)
			return nil
		},
	}
}

// writeKeyTable renders the key table (shared with the TUI once it reaches CLI
// parity).
func writeKeyTable(out io.Writer, rows []keysvc.Row) {
	if len(rows) == 0 {
		fmt.Fprintln(out, "no keys in the manifest (add one with `sshmgr key add`)")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tTYPE\tFINGERPRINT\tEXPIRES\tHOSTS\tSTATE")
	for _, r := range rows {
		state := r.Status
		if notes := keyaudit.Notes(r); len(notes) > 0 {
			state += "  " + strings.Join(notes, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Ref, r.Type, dash(r.Fingerprint), dash(r.ExpiresOn), dash(strings.Join(r.Hosts, ",")), state)
	}
	_ = tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
