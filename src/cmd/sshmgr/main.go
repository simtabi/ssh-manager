// Command sshmgr is the ssh-manager binary: a profile-based SSH key and config
// lifecycle manager. As of v2 it is a single self-contained Go program with no
// Python runtime - every verb is native Go.
package main

import (
	"os"

	"github.com/simtabi/ssh-manager/src/v3/internal/cli"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/askpass"
)

func main() {
	// ssh-keygen re-executes this binary as its askpass helper and passes the
	// prompt text as an argument. That is not a sshmgr verb, so it has to be
	// answered before the command line is parsed.
	if askpass.Serving() {
		os.Exit(askpass.Serve(os.Stdout))
	}
	cli.Execute()
}
