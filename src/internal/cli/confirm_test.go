package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Ports python-final:tests/test_cli_yes.py. --yes is the flag that makes
// deletion usable from a script or a cron job, and the property it has to carry
// is that no prompt is reached at all - not that a prompt is answered for you.
// The tests below give the command an empty reader, so any prompt it does reach
// hits EOF and declines: with --yes working the deletion still goes through,
// and without it the command aborts.

// runIn is runErr with a specific stdin, so a prompt's behaviour is decidable
// rather than dependent on how the test binary happened to be invoked.
func runIn(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	// Execute first: the two return expressions are evaluated left to right, so
	// reading the buffer inline would capture it before the command ran.
	err := root.Execute()
	return out.String(), err
}

func TestYesMakesHostDeleteNonInteractive(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "tp")
	run(t, "host", "add", "tp", "web1", "-H", "web1.example.com", "-u", "deploy")

	// No input at all: every prompt would read EOF and decline.
	out, err := runIn(t, "", "host", "delete", "tp", "web1", "--yes")
	if err != nil {
		t.Fatalf("--yes should not need an answer: %v\n%s", err, out)
	}
	if listing := run(t, "list"); strings.Contains(listing, "web1") {
		t.Errorf("the host survived the delete:\n%s", listing)
	}
}

func TestYesMakesProfileDeleteNonInteractive(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "tp2")

	out, err := runIn(t, "", "profile", "delete", "tp2", "--yes")
	if err != nil {
		t.Fatalf("--yes should not need an answer: %v\n%s", err, out)
	}
	if listing := run(t, "list"); strings.Contains(listing, "tp2") {
		t.Errorf("the profile survived the delete:\n%s", listing)
	}
}

// Without --yes the prompt is real, and declining it has to leave everything
// alone. It exits non-zero so a script that pipes "n" does not read as success,
// and silently, because the user already knows what they answered.
func TestDecliningTheConfirmationChangesNothing(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "tp3")

	out, err := runIn(t, "n\n", "profile", "delete", "tp3")
	if err == nil {
		t.Fatal("declining the confirmation should not report success")
	}
	if !errors.Is(err, errAborted) {
		t.Errorf("err = %v, want the abort sentinel so nothing is printed over it", err)
	}
	if !silent(err) {
		t.Error("an abort should exit quietly; the user knows what they answered")
	}
	if !strings.Contains(out, "[y/N]") {
		t.Errorf("the prompt should have been shown:\n%s", out)
	}
	if listing := run(t, "list"); !strings.Contains(listing, "tp3") {
		t.Errorf("declining still deleted the profile:\n%s", listing)
	}
}

// "y" is an answer too, and it has to reach the same place --yes does.
func TestAcceptingTheConfirmationProceeds(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "tp4")

	// One "y" per prompt; extra lines are harmless if fewer are asked.
	out, err := runIn(t, "y\ny\ny\n", "profile", "delete", "tp4")
	if err != nil {
		t.Fatalf("answering yes should proceed: %v\n%s", err, out)
	}
	if listing := run(t, "list"); strings.Contains(listing, "tp4") {
		t.Errorf("the profile survived an accepted delete:\n%s", listing)
	}
}

// Anything that is not y/yes declines. A prompt that treated an accidental
// keystroke as consent would delete a profile on a stray character.
func TestOnlyYesAccepts(t *testing.T) {
	for _, answer := range []string{"", "n\n", "no\n", "\n", "yy\n", "Y E S\n", "q\n"} {
		editHome(t)
		run(t, "profile", "add", "tp5")
		if _, err := runIn(t, answer, "profile", "delete", "tp5"); err == nil {
			t.Errorf("%q was treated as consent", answer)
		}
	}
	// ...and the two spellings that do accept, either case.
	for _, answer := range []string{"y\ny\ny\n", "YES\nYES\nYES\n"} {
		editHome(t)
		run(t, "profile", "add", "tp6")
		if _, err := runIn(t, answer, "profile", "delete", "tp6"); err != nil {
			t.Errorf("%q should be accepted: %v", answer, err)
		}
	}
}
