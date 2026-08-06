package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// Dev mode: run the whole tool against a scratch directory instead of ~/.ssh.
//
// Before this there was no way to do it. The config home had an override
// ($SSH_MANAGER_HOME) but ~/.ssh had none - every call site asked for
// paths.Resolve(nil, "", ""), whose empty third argument means $HOME/.ssh - so
// exercising anything that mints, renders or pins wrote into the tree you
// actually use. The alternative, moving $HOME, also moves the ssh-agent socket
// and the launchd session, so it changes what is being tested.

const devRootFlag = "dev-root"

// devRootOf returns the sandbox root for this invocation: the flag if given,
// else $SSHMGR_DEV_ROOT, else "".
//
// The flag is read off the root command rather than a package-level variable so
// that a test building its own command tree gets its own value - a global here
// would leak between tests and, worse, between a test and the real user's home.
func devRootOf(c *cobra.Command) string {
	if c != nil {
		if v, err := c.Root().PersistentFlags().GetString(devRootFlag); err == nil && v != "" {
			return v
		}
	}
	return os.Getenv(paths.DevRootEnv)
}

// resolvePaths is the single place the on-disk layout is decided.
//
// Every verb goes through it, so dev mode cannot be half-applied: there is no
// path by which one command reads the sandbox and another writes the real tree.
// It also announces itself, on stderr, every time. A sandbox you cannot see is
// the same hazard as no sandbox - you find out which tree you were in by looking
// at the damage - and stderr keeps the announcement out of any parsed output.
func resolvePaths(c *cobra.Command) (paths.Paths, error) {
	root := devRootOf(c)
	if root == "" {
		return paths.Resolve(nil, "", ""), nil
	}
	p, err := paths.ResolveDev(nil, "", root)
	if err != nil {
		return paths.Paths{}, err
	}
	if c != nil {
		_, _ = fmt.Fprintf(c.ErrOrStderr(),
			"sshmgr: dev mode - writing under %s, not %s\n", p.DevRoot, paths.Resolve(nil, "", "").SSHDir)
	}
	return p, nil
}

// refuseInDevMode blocks the actions a sandbox cannot contain.
//
// Everything else this tool does is a file under one of two directories, and
// pointing those at a scratch root is the whole of dev mode. These two are not
// files: `notify install` registers a job with launchd, systemd or schtasks -
// real, machine-wide, and still there after the sandbox is deleted - and
// `deploy` uploads a public key to a live account. Letting either run under a
// flag whose entire promise is "this does not touch anything real" would make
// the promise false in exactly the cases that matter.
func refuseInDevMode(p paths.Paths, action, because string) error {
	if !p.IsDev() {
		return nil
	}
	return fmt.Errorf("%s is refused in dev mode: %s.\n"+
		"Dev mode sandboxes files under %s, and this would take effect outside it",
		action, because, p.DevRoot)
}
