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
	// "init" is now native Go (see init.go), not a passthrough.
	// "migrate" is now native Go (see migrate.go), not a passthrough.
	// "doctor" is now native Go (see doctor.go), not a passthrough.
	// "reconcile" is now native Go (see reconcile.go), not a passthrough.
	// "keygen" is now native Go (see keygen.go), not a passthrough.
	// "config" is now native Go (see config.go), not a passthrough.
	// "import" is now native Go (see import.go), not a passthrough.
	// "diff" is now native Go (see diff.go), not a passthrough.
	{"list", "Filterable tree across profiles"},
	{"view", "Resolved host config + key + deployment status"},
	// "validate" is now native Go (see validate.go), not a passthrough.
	// "providers" is now native Go (see providers.go), not a passthrough.
	// "net" is now native Go (see net.go), not a passthrough.
	{"deploy", "Install a public key on its target"},
	// "load" is now native Go (see load.go), not a passthrough.
	{"audit", "Deployment, expiry, and hygiene report"},
	{"expiry", "Per-key rotation-age table"},
	{"rotate", "Zero-downtime staged key rotation"},
	{"rollback", "Restore the previous key"},
	{"bundle", "Encrypted backup of keys + state"},
	{"restore", "Decrypt and lay keys back"},
	// "snapshots" is now native Go (see snapshots.go), not a passthrough.
	{"recover", "Break-glass recovery snippet / fixkeys tool"},
	{"notify", "Manage the scheduled expiry notifier"},
	// "profile" is now native Go (see profile.go), not a passthrough.
	// "host" is now native Go (see host.go), not a passthrough.
	// "knownhosts" is now native Go (see knownhosts.go), not a passthrough.
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
