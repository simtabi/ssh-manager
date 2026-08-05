package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// scriptPrompter replays scripted Select/Confirm answers so the TUI navigation
// loop is testable without a TTY (mirrors tui.py's injected fake).
type scriptPrompter struct {
	selects []string // "" => cancel (ok=false)
	si      int
}

func (s *scriptPrompter) Select(_ string, _ []string) (string, bool) {
	if s.si >= len(s.selects) {
		return "", false // exhausted -> cancel, ends the loop
	}
	v := s.selects[s.si]
	s.si++
	return v, v != ""
}
func (s *scriptPrompter) Confirm(string) bool { return false }

func tuiWith(t *testing.T, selects ...string) (*tui, *bytes.Buffer) {
	t.Helper()
	base := t.TempDir()
	cfg := filepath.Join(base, "cfg")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	mj := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	_ = os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte(mj), 0o600)
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: cfg}
	var buf bytes.Buffer
	return &tui{p: p, pr: &scriptPrompter{selects: selects}, out: &buf}, &buf
}

func TestTuiQuitImmediately(t *testing.T) {
	tt, buf := tuiWith(t, "Quit")
	tt.run()
	if strings.Contains(buf.String(), "panic") {
		t.Error("unexpected output")
	}
}

func TestTuiReadVerbs(t *testing.T) {
	// Expiry -> Audit -> Show rendered config -> Quit.
	tt, buf := tuiWith(t, "Expiry status", "Audit (deployments + expiry)", "Show rendered config", "Quit")
	tt.run()
	out := buf.String()
	for _, want := range []string{
		"no keys tracked",     // expiry with empty inventory
		"=== deployments ===", // audit
		"=== expiry ===",      // audit
		"# --- profile: work", // show rendered config (hosts render inline now)
	} {
		if !strings.Contains(out, want) {
			t.Errorf("TUI output missing %q\n%s", want, out)
		}
	}
}

func TestTuiBrowse(t *testing.T) {
	// Browse -> profile "work" -> host "gh" -> back to menu -> Quit.
	tt, buf := tuiWith(t, "Browse profiles & hosts", "work", "gh", "Quit")
	tt.run()
	out := buf.String()
	if !strings.Contains(out, "profile work") {
		t.Errorf("browse should show the profile summary:\n%s", out)
	}
	if !strings.Contains(out, "gh  (profile work)") {
		t.Errorf("browse should show the host detail:\n%s", out)
	}
}

func TestTuiCancelEndsLoop(t *testing.T) {
	// An empty (cancel) selection ends the loop cleanly.
	tt, _ := tuiWith(t, "")
	tt.run()
}

// The TUI's own prompter, not the scripted fake. The four tests above inject a
// prompter and so never touch the real one - which read os.Stdin directly,
// meaning the menu could only ever be driven by a terminal and the whole
// production path went unexercised. It now reads the command's input, so the
// menu is drivable the same way every other prompt in the tool is.
func TestTheRealPrompterReadsTheCommandsInput(t *testing.T) {
	var out bytes.Buffer
	pr := newStdinPrompter(&out, strings.NewReader("2\ny\n"))

	choice, ok := pr.Select("pick one", []string{"first", "second", "third"})
	if !ok {
		t.Fatal("a valid numbered answer should select")
	}
	if choice != "second" {
		t.Errorf("choice = %q, want the second entry", choice)
	}
	if !strings.Contains(out.String(), "1) first") || !strings.Contains(out.String(), "3) third") {
		t.Errorf("the menu should be numbered from 1:\n%s", out.String())
	}
	if !pr.Confirm("really?") {
		t.Error("y should confirm")
	}
}

// Out-of-range and unparseable answers cancel rather than selecting something
// the user did not ask for. A menu that treated a stray key as a choice would
// run whichever action happened to be first.
func TestTheRealPrompterCancelsOnAnythingThatIsNotAChoice(t *testing.T) {
	for _, answer := range []string{"", "0\n", "4\n", "-1\n", "two\n", "\n", "1x\n"} {
		var out bytes.Buffer
		pr := newStdinPrompter(&out, strings.NewReader(answer))
		if _, ok := pr.Select("pick one", []string{"a", "b", "c"}); ok {
			t.Errorf("%q was treated as a selection", answer)
		}
	}
}

// EOF on the menu ends the session rather than looping forever on a closed
// input - which is what a piped or scripted invocation gives it.
func TestTheTUIEndsWhenItsInputIsClosed(t *testing.T) {
	var out bytes.Buffer
	pr := newStdinPrompter(&out, strings.NewReader(""))
	if _, ok := pr.Select("pick one", []string{"a"}); ok {
		t.Error("closed input should cancel, not select")
	}
	if pr.Confirm("really?") {
		t.Error("closed input should decline a confirmation")
	}
}
