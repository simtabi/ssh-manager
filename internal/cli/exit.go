package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// The exit-code contract, and the one place it is applied.
//
// Parity with the Python implementation is a plain binary: 0 on success, 1 on
// anything else. `_fail` mapped every SshManagerError to `typer.Exit(code=1)`,
// a declined confirmation raised `typer.Exit(code=1)`, and `doctor` exited
// `0 if report.ok else 1` (python-final:src/ssh_manager/cli.py:59-62, :147,
// :343-344). No other code was ever produced, so none is invented here.
//
// What changes is where it is decided. Commands used to call os.Exit(1) inline,
// in fourteen places across the CLI. That is unreachable from a test - os.Exit
// takes the test binary with it - so no command could be exercised end to end
// through Execute, which is exactly the gate this migration needs. It also
// skipped every deferred function on the way out.
//
// So: a command returns an error, always, and Execute turns it into a code.

// errAborted is returned when the user declines a confirmation. It exits 1 like
// any other failure, but silently: the prompt already said what happened, and
// "sshmgr: aborted" underneath it reads like a fault rather than a choice.
var errAborted = errors.New("aborted at the user's request")

// errNotClean is returned by a command whose *report* is the failure - doctor
// finding problems, validate finding a broken key. The report has already been
// printed in full; the exit code is the machine-readable half of it.
var errNotClean = errors.New("checks reported problems")

// silent reports whether an error is one whose message has already reached the
// user by another route.
func silent(err error) bool {
	return errors.Is(err, errAborted) || errors.Is(err, errNotClean)
}

// Execute runs the root command and is the only place in the binary that maps
// an outcome to an exit code.
func Execute() {
	err := newRootCmd().Execute()
	if err == nil {
		return
	}
	if !silent(err) {
		fmt.Fprintln(os.Stderr, "sshmgr:", err)
	}
	os.Exit(1)
}

// confirmOrAbort runs a confirmation and converts a "no" into errAborted, so a
// declining user gets the same exit code as before without a command having to
// reach for os.Exit.
func confirmOrAbort(c *cobra.Command, prompt string, skip bool) error {
	if skip || confirm(c, prompt) {
		return nil
	}
	return errAborted
}
