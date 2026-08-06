package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Python's contract, from python-final:src/ssh_manager/cli.py: `_fail` mapped
// every SshManagerError to typer.Exit(code=1) (:59-62), a declined confirmation
// raised typer.Exit(code=1) (:343-344, :357-358, :462-463, :543-544, :606-607),
// and doctor exited `0 if report.ok else 1` (:147). Success was 0. Nothing else
// was ever produced.
//
// Go cannot assert the code without spawning a process, so what is asserted here
// is the classification that Execute turns into one - and, separately, that no
// command reaches for os.Exit itself, which is what made this untestable before.
func TestErrorClassification(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantSilent bool
	}{
		{"a declined confirmation is silent", errAborted, true},
		{"a wrapped abort is still silent", errors.New("x: " + errAborted.Error()), false},
		{"a wrapped abort via %w is silent", wrap(errAborted), true},
		{"a failing report is silent", errNotClean, true},
		{"an ordinary failure is reported", errors.New("manifest not found"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := silent(c.err); got != c.wantSilent {
				t.Errorf("silent(%v) = %v, want %v", c.err, got, c.wantSilent)
			}
		})
	}
}

func wrap(err error) error { return errWrapper{err} }

type errWrapper struct{ err error }

func (e errWrapper) Error() string { return "while doing the thing: " + e.err.Error() }
func (e errWrapper) Unwrap() error { return e.err }

// A declined confirmation must fail, and must not print a second line under the
// prompt - "sshmgr: aborted" reads like a fault rather than the answer given.
func TestConfirmOrAbort(t *testing.T) {
	c := &cobra.Command{}
	var out bytes.Buffer
	c.SetOut(&out)

	// --yes short-circuits without consulting the terminal at all.
	if err := confirmOrAbort(c, "Delete everything?", true); err != nil {
		t.Errorf("--yes should skip the prompt: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("--yes should not have printed a prompt: %q", out.String())
	}

	// Declining is an error, and it is the silent kind.
	c.SetIn(strings.NewReader("n\n"))
	err := confirmOrAbort(c, "Delete everything?", false)
	if !errors.Is(err, errAborted) {
		t.Fatalf("declining should return errAborted, got %v", err)
	}
	if !silent(err) {
		t.Error("a declined confirmation should not print an error line of its own")
	}
}

// The regression this whole file exists to prevent: a command that calls
// os.Exit cannot be tested through Execute, because it takes the test binary
// with it. Exit codes belong to Execute alone.
func TestNoCommandCallsOsExit(t *testing.T) {
	files, err := packageSources()
	if err != nil {
		t.Fatal(err)
	}
	for path, src := range files {
		if path == "exit.go" {
			continue // Execute is the one place allowed to
		}
		if strings.Contains(stripComments(src), "os.Exit(") {
			t.Errorf("%s calls os.Exit: return an error instead, so the command "+
				"can be exercised through Execute", path)
		}
	}
}

// packageSources reads this package's own non-test source, keyed by base name.
// The test runs in the package directory, so "." is that package.
func packageSources() (map[string]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		out[name] = string(b)
	}
	return out, nil
}

// stripComments removes line comments so a mention of os.Exit in prose does not
// read as a call. Block comments are not handled - this package has none, and a
// false positive here is a test failure telling you to look, not a silent miss.
func stripComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
