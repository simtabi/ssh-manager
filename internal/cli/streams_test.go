package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Every prompt and every message belongs to the command that raised it, not to
// the process. Three places reached past the command to os.Stdin/os.Stderr
// directly: the TUI's prompter, readPassphrase's piped branch, and notify test's
// "no backend" line. Each was unreachable through Execute as a result - which is
// why the rows covering them could not be verified - and each ignored a caller
// that redirected its streams.
//
// internal/cli/snapshots.go's confirm() is the pattern; these three never got it.

// readPassphrase's piped branch reads a single line from the command's input.
// It reads one line rather than buffering, because the terminal branch reads a
// second line to confirm and a buffered reader would have swallowed it.
func TestReadPassphraseReadsThePipedLineFromTheCommand(t *testing.T) {
	in := strings.NewReader("correct horse battery staple\nnot this line\n")

	got, err := readPassphrase(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != "correct horse battery staple" {
		t.Errorf("passphrase = %q, want the first line only", got)
	}
	// The rest of the input is still there for whatever reads next.
	rest, err := readPassphrase(in)
	if err != nil {
		t.Fatal(err)
	}
	if rest != "not this line" {
		t.Errorf("the reader consumed past its line: next read = %q", rest)
	}
}

// An empty passphrase is a real answer - it means "do not protect the key" -
// and must come back as empty rather than as an error.
func TestReadPassphraseAcceptsAnEmptyLine(t *testing.T) {
	got, err := readPassphrase(strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("an empty passphrase is a valid answer: %v", err)
	}
	if got != "" {
		t.Errorf("passphrase = %q, want empty", got)
	}
}

// notify test reports a missing backend on the command's error stream, so
// `sshmgr notify test > log` does not silently discard the one line that
// explains why nothing appeared on screen.
func TestNotifyTestReportsAMissingBackendOnStderr(t *testing.T) {
	editHome(t)
	t.Setenv("PATH", t.TempDir()) // no notification backend reachable

	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"notify", "test"})
	if err := root.Execute(); err != nil {
		t.Fatalf("notify test should not fail when no backend exists: %v", err)
	}
	if !strings.Contains(errOut.String(), "no notification backend") {
		t.Errorf("stderr = %q, want the missing-backend line", errOut.String())
	}
	if strings.Contains(out.String(), "no notification backend") {
		t.Errorf("the diagnostic went to stdout:\n%s", out.String())
	}
}

// The general rule, asserted directly: a command's own writers are what get
// written to. Each verb below is given something to report, so silence here
// means the output went to the process's streams rather than the command's.
func TestCommandsWriteToTheirOwnStreams(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	for _, args := range [][]string{
		{"version"},
		{"list"},
		{"view", "gh"},
		{"providers"},
	} {
		root := newRootCmd()
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		root.SetIn(strings.NewReader(""))
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if out.Len() == 0 && errOut.Len() == 0 {
			t.Errorf("%v wrote nothing to the command's streams; it went somewhere else", args)
		}
	}
}

// editHome must isolate the home on every platform. paths.home() reads
// USERPROFILE on Windows and HOME elsewhere, so setting only HOME left the
// whole internal/cli suite resolving ~/.ssh to the developer's real home - which
// went unnoticed because CI had never run the Go suite on Windows. Eleven tests
// failed there the first time it did.
func TestEditHomeIsolatesTheHomeOnEveryPlatform(t *testing.T) {
	p := editHome(t)

	for _, v := range []string{"HOME", "USERPROFILE"} {
		got := os.Getenv(v)
		if got == "" {
			t.Errorf("%s is unset; the home is not isolated on the platform that reads it", v)
			continue
		}
		if !strings.HasPrefix(filepath.ToSlash(p.SSHDir), filepath.ToSlash(got)) {
			t.Errorf("%s = %q but SSHDir is %q; they must agree", v, got, p.SSHDir)
		}
	}
	// And the resolver agrees, through the same code the commands use.
	if got := paths.Resolve(nil, "", "").SSHDir; got != p.SSHDir {
		t.Errorf("paths.Resolve gives %q, the fixture says %q", got, p.SSHDir)
	}
}
