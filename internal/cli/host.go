package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/services/editor"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func intPtrIf(cmd *cobra.Command, flag string, val int) *int {
	if cmd.Flags().Changed(flag) {
		return &val
	}
	return nil
}

func newHostCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "host", Short: "Manage a host within a profile (add/edit/delete)"}

	var hostname, user, provider, tokenEnv, keyName string
	var port int
	var tags []string
	add := &cobra.Command{
		Use:   "add <profile> <alias>",
		Short: "Add a host to a profile",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			ed := editor.New(paths.Resolve(nil, "", ""))
			f := editor.HostFields{
				Hostname: &hostname, User: &user, Port: &port,
				Provider: strPtrIf(c, "provider", provider),
				TokenEnv: strPtrIf(c, "token-env", tokenEnv),
				KeyName:  strPtrIf(c, "key-name", keyName),
				Tags:     tags,
			}
			if err := ed.AddHost(args[0], args[1], f); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "added host %s to %s. Run `sshmgr reconcile` to apply.\n", args[1], args[0])
			return nil
		},
	}
	add.Flags().StringVarP(&hostname, "hostname", "H", "", "host to connect to")
	add.Flags().StringVarP(&user, "user", "u", "", "ssh user")
	add.Flags().IntVarP(&port, "port", "p", 22, "ssh port")
	add.Flags().StringVar(&provider, "provider", "", "")
	add.Flags().StringVar(&tokenEnv, "token-env", "", "")
	add.Flags().StringVar(&keyName, "key-name", "", "")
	add.Flags().StringArrayVar(&tags, "tag", nil, "repeatable")
	_ = add.MarkFlagRequired("hostname")
	_ = add.MarkFlagRequired("user")
	cmd.AddCommand(add)

	var eHostname, eUser, eProvider, eTokenEnv, eKeyName string
	var ePort int
	edit := &cobra.Command{
		Use:   "edit <profile> <alias>",
		Short: "Edit a host",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			ed := editor.New(paths.Resolve(nil, "", ""))
			f := editor.HostFields{
				Hostname: strPtrIf(c, "hostname", eHostname),
				User:     strPtrIf(c, "user", eUser),
				Port:     intPtrIf(c, "port", ePort),
				Provider: strPtrIf(c, "provider", eProvider),
				TokenEnv: strPtrIf(c, "token-env", eTokenEnv),
				KeyName:  strPtrIf(c, "key-name", eKeyName),
			}
			if err := ed.EditHost(args[0], args[1], f); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "edited host %s. Run `sshmgr reconcile` to apply.\n", args[1])
			return nil
		},
	}
	edit.Flags().StringVarP(&eHostname, "hostname", "H", "", "")
	edit.Flags().StringVarP(&eUser, "user", "u", "", "")
	edit.Flags().IntVarP(&ePort, "port", "p", 22, "")
	edit.Flags().StringVar(&eProvider, "provider", "", "")
	edit.Flags().StringVar(&eTokenEnv, "token-env", "", "")
	edit.Flags().StringVar(&eKeyName, "key-name", "", "")
	cmd.AddCommand(edit)

	var yes, revoke bool
	del := &cobra.Command{
		Use:   "delete <profile> <alias>",
		Short: "Delete a host (prompts to revoke + prune)",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			if !yes && !confirm(c, fmt.Sprintf("Delete host %q from %q?", args[1], args[0])) {
				os.Exit(1)
			}
			doRevoke := revoke
			if !yes {
				doRevoke = confirm(c, "Revoke the deployed public key from its targets first?")
			}
			ed := editor.New(paths.Resolve(nil, "", ""))
			res, err := ed.DeleteHost(args[0], args[1], doRevoke)
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), res.Format())
			return nil
		},
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation prompts")
	del.Flags().BoolVar(&revoke, "revoke", false, "also revoke the deployed key from targets (with --yes)")
	cmd.AddCommand(del)

	return cmd
}
