package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/version"
)

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version command errored: %v", err)
	}
	want := "sshmgr " + version.Version + "\n"
	if out.String() != want {
		t.Fatalf("version output = %q, want %q", out.String(), want)
	}
}

func TestRootHasVersionFlag(t *testing.T) {
	root := newRootCmd()
	if root.Version != version.Version {
		t.Fatalf("root.Version = %q, want %q", root.Version, version.Version)
	}
}

// A command this build does not have, followed by a flag, used to be reported
// as "unknown flag: --open": cobra parses the root's flags before it notices
// the word is not a command, so an old binary hid the real problem (it has no
// `termius`) behind a complaint about the flag.
func TestUnknownCommandIsReportedBeforeItsFlags(t *testing.T) {
	editHome(t)
	for _, args := range [][]string{
		{"nosuchcmd", "export", "--open"},
		{"nosuchcmd", "--open"},
	} {
		_, err := runErr(t, args...)
		if err == nil || !strings.Contains(err.Error(), `unknown command "nosuchcmd"`) {
			t.Errorf("%v: got %v", args, err)
		}
	}
	// A real command's unknown flag is still a flag error.
	if _, err := runErr(t, "termius", "export", "--nope"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("a known command's bad flag: %v", err)
	}
	// And a near miss still gets cobra's suggestion.
	for _, args := range [][]string{{"termus", "export", "--open"}, {"termus"}} {
		if _, err := runErr(t, args...); err == nil || !strings.Contains(err.Error(), "Did you mean this?\n\ttermius") {
			t.Errorf("%v: a typo should suggest the command: %v", args, err)
		}
	}
}
