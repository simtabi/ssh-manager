package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/engine"
)

// v1Verbs are the ssh-manager commands not yet ported to Go. Each forwards
// verbatim to the engine (flags and subcommands included), so behavior matches
// v1 exactly. As a verb is ported, it moves out of this list to a native Go
// command. `version` is already native; `tui` becomes native in the TUI wave.
var v1Verbs = []struct{ verb, short string }{
	{"init", "Create/converge the per-user home"},
	{"migrate", "Move a legacy home to the standard location"},
	{"doctor", "Diagnose deps, perms, agent, known_hosts, drift"},
	{"reconcile", "Build ~/.ssh from the manifest"},
	{"keygen", "Generate a profile's or host's keys"},
	// "config" is now native Go (see config.go), not a passthrough.
	{"import", "Onboard an existing ~/.ssh into the manifest"},
	{"diff", "Preview manifest vs. on-disk reality"},
	{"list", "Filterable tree across profiles"},
	{"view", "Resolved host config + key + deployment status"},
	// "validate" is now native Go (see validate.go), not a passthrough.
	{"providers", "List the active provider catalog + credential state"},
	{"net", "Per-host connection status + VPN indicator"},
	{"deploy", "Install a public key on its target"},
	{"load", "Add a profile's keys to the agent"},
	{"audit", "Deployment, expiry, and hygiene report"},
	{"expiry", "Per-key rotation-age table"},
	{"rotate", "Zero-downtime staged key rotation"},
	{"rollback", "Restore the previous key"},
	{"bundle", "Encrypted backup of keys + state"},
	{"restore", "Decrypt and lay keys back"},
	{"snapshots", "List/restore/prune local ~/.ssh backups"},
	{"recover", "Break-glass recovery snippet / fixkeys tool"},
	{"notify", "Manage the scheduled expiry notifier"},
	{"profile", "Manage a profile (add/edit/delete)"},
	{"host", "Manage a host within a profile (add/edit/delete)"},
	{"knownhosts", "Initialize/pin per-profile known_hosts"},
}

// newPassthroughCmd builds a command that forwards the whole invocation to the
// engine. Flag parsing is disabled so flags and nested subcommands reach the
// engine unchanged; the engine owns their help and validation.
func newPassthroughCmd(verb, short string) *cobra.Command {
	return &cobra.Command{
		Use:                verb,
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(_ *cobra.Command, args []string) error {
			code, err := engine.Run(append([]string{verb}, args...))
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}

func addPassthroughCommands(root *cobra.Command) {
	for _, v := range v1Verbs {
		root.AddCommand(newPassthroughCmd(v.verb, v.short))
	}
}
