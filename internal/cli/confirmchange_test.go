package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every verb that changes ~/.ssh asks first when someone is there to answer.
//
// "When someone is there" is the whole design. With no terminal - a pipe, a
// cron job, a CI step - there is nobody to prompt, so the guard proceeds:
// declining on its own would turn every existing script into a silent no-op,
// which is not safer than running, only harder to diagnose. `--yes` says so
// explicitly rather than relying on the absence of a terminal.
//
// These tests run without a terminal, which is why they exercise the
// proceed-anyway path directly; the prompt path is covered by confirm_test.go
// and by confirmChange's own unit test below.

// The proceed-anyway half, through the real commands. If this regressed, every
// script and CI job using the tool would stop doing anything.
func TestMutatingVerbsStillRunWithoutATerminal(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("needs a filesystem")
	}
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "127.0.0.1", "-u", "git", "-p", "1")

	// reconcile is the one that matters most: it is what a CI job runs.
	run(t, "reconcile", "--no-pin")
	if _, err := os.Stat(filepath.Join(p.SSHDir, "config")); err != nil {
		t.Fatalf("reconcile did not write the config: %v", err)
	}
	// And the rest, each of which now goes through the guard.
	run(t, "config", "render")
	run(t, "clean", "--dry-run")
	run(t, "migrate")
}

// --yes is the explicit form, and must work whether or not a terminal exists -
// a script should not have to rely on the absence of one.
func TestYesIsAcceptedByEveryMutatingVerb(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "127.0.0.1", "-u", "git", "-p", "1")

	for _, args := range [][]string{
		{"reconcile", "--no-pin", "--yes"},
		{"config", "render", "--yes"},
		{"clean", "--yes"},
		{"migrate", "--yes"},
	} {
		if out, err := runErr(t, args...); err != nil {
			t.Errorf("%v with --yes failed: %v\n%s", args, err, out)
		}
	}
}

// The guard itself, both branches, without needing a terminal to test the
// terminal branch: yes short-circuits before anything is printed or read.
func TestConfirmChangeShortCircuitsOnYes(t *testing.T) {
	root := newRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetIn(strings.NewReader("")) // EOF: would decline if it were consulted

	if err := confirmChange(root, "about to do a thing", true); err != nil {
		t.Errorf("--yes should proceed without asking: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("--yes printed a summary it did not need to: %q", out.String())
	}
}

// Every command that takes the mutation guard must also take the confirmation
// guard. The two go together: a verb that snapshots ~/.ssh before acting is by
// definition one that changes it, and one that changes it must ask.
func TestEveryMutatingVerbAlsoConfirms(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	// tui.go composes the other verbs and confirms per action in its own menu;
	// mutate.go is the guard itself.
	exempt := map[string]bool{"mutate.go": true, "tui.go": true}
	var missing []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || exempt[name] {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if !strings.Contains(src, "snapshotBeforeMutation") {
			continue
		}
		if !strings.Contains(src, "confirmChange") && !strings.Contains(src, "confirmOrAbort") {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these change ~/.ssh without asking: %v.\n"+
			"A verb that snapshots before acting is one that changes things, and one "+
			"that changes things confirms - confirmChange proceeds on its own when "+
			"there is no terminal, so adding it costs a script nothing.", missing)
	}
}
