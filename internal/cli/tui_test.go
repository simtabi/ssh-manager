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
	os.MkdirAll(cfg, 0o700)
	mj := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte(mj), 0o600)
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
		"Include profiles",    // show rendered config (root config includes profiles)
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
