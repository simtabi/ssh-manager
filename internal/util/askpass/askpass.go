// Package askpass delivers a passphrase to ssh-keygen without it ever appearing
// on a command line.
//
// ssh-keygen's -N flag is unusable for a real passphrase: argv is world-readable
// through ps and /proc/<pid>/cmdline, so every local user can read it for as long
// as the process runs. Piping to stdin does not work either, because ssh-keygen
// asks via readpassphrase(3), which opens /dev/tty in preference to stdin
// whenever a terminal exists.
//
// What does work is the askpass protocol: ssh-keygen executes the program named
// by SSH_ASKPASS and reads the passphrase from its standard output. sshmgr names
// itself, so no separate helper binary has to be installed or trusted.
package askpass

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// modeVar marks a re-execution of sshmgr as its own askpass helper.
	modeVar = "SSHMGR_ASKPASS_MODE"
	// secretVar carries the passphrase to that helper. A process environment is
	// readable only by its own user and root, unlike argv, which is readable by
	// every local user.
	secretVar = "SSHMGR_ASKPASS_SECRET"
)

// Serving reports whether this process was executed by ssh-keygen as an askpass
// helper rather than invoked by the user. ssh-keygen passes the prompt text as an
// argument, which is not a sshmgr command, so this has to be checked before the
// command line is parsed.
func Serving() bool { return os.Getenv(modeVar) == "1" }

// Serve writes the passphrase for ssh-keygen to read and reports the process
// exit code.
func Serve(w io.Writer) int {
	fmt.Fprintln(w, os.Getenv(secretVar))
	return 0
}

// Environ returns the full child environment for an ssh-keygen invocation that
// should ask self for the passphrase.
//
// SSH_ASKPASS_REQUIRE=force (OpenSSH 8.4 and later) is what makes this work with
// a terminal attached; without it ssh-keygen reads /dev/tty directly and ignores
// the helper. Older ssh-keygen ignores the variable and falls back to prompting
// on the terminal, or to reading stdin when there is no terminal - both of which
// keep the passphrase off the command line, so no version check is needed.
func Environ(self, secret string) []string {
	overlay := map[string]string{
		"SSH_ASKPASS":         self,
		"SSH_ASKPASS_REQUIRE": "force",
		modeVar:               "1",
		secretVar:             secret,
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		// Drop any inherited value: getenv returns the first match, so appending
		// an override would not reliably win.
		if ok {
			if _, replaced := overlay[name]; replaced {
				continue
			}
		}
		env = append(env, kv)
	}
	for name, value := range overlay {
		env = append(env, name+"="+value)
	}
	return env
}
