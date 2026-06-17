// Command sshmgr is the ssh-manager binary: a profile-based SSH key and config
// lifecycle manager. As of v2 it is a single self-contained Go program with no
// Python runtime - every verb is native Go.
package main

import "github.com/simtabi/ssh-manager/internal/cli"

func main() {
	cli.Execute()
}
