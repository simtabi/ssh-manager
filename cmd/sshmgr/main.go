// Command sshmgr is the ssh-manager binary: a profile-based SSH key and config
// lifecycle manager. v2 is a Go front-end over the ssh-manager engine, migrating
// to pure Go over the v2.x line.
package main

import "github.com/simtabi/ssh-manager/internal/cli"

func main() {
	cli.Execute()
}
