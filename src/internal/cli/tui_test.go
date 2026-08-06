package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// scriptPrompter replays scripted answers so the TUI navigation loop is testable
// without a TTY. One queue feeds both prompts, so a script reads like a
// transcript of what someone types: a root-menu answer, then whatever sub-menu
// it opens.
type scriptPrompter struct {
	answers []string
	i       int
	confirm bool
}

// next models the real prompter's two distinct outcomes. Running out of answers
// is EOF (ok=false); an empty answer is a user pressing Enter (ok=true, empty),
// which is a thing the menu handles differently. The fake used to return
// ok=false for both, so "the user pressed Enter" was untestable - it looked
// identical to a closed input.
func (s *scriptPrompter) next() (string, bool) {
	if s.i >= len(s.answers) {
		return "", false // exhausted -> EOF, ends the loop
	}
	v := s.answers[s.i]
	s.i++
	return v, true
}

func (s *scriptPrompter) Line(string) (string, bool) { return s.next() }

// Select validates against the offered choices rather than returning whatever
// was scripted. The looser version let a test "select" an entry the menu was
// not actually showing, which is the one thing a menu test must not do.
func (s *scriptPrompter) Select(_ string, choices []string) (string, bool) {
	v, ok := s.next()
	if !ok {
		return "", false
	}
	for _, c := range choices {
		if c == v {
			return c, true
		}
	}
	return "", false
}
func (s *scriptPrompter) Confirm(string) bool { return s.confirm }

func tuiWith(t *testing.T, answers ...string) (*tui, *bytes.Buffer) {
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
	return &tui{p: p, pr: &scriptPrompter{answers: answers}, out: &buf}, &buf
}

func TestTuiQuitImmediately(t *testing.T) {
	tt, buf := tuiWith(t, "q")
	tt.run()
	if strings.Contains(buf.String(), "panic") {
		t.Error("unexpected output")
	}
}

func TestTuiReadVerbs(t *testing.T) {
	// Answers are the verbs the menu prints in its right-hand column, which is
	// exactly what a user can type.
	tt, buf := tuiWith(t, "expiry", "audit", "config show", "q")
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
	// Browse -> profile "work" -> host "gh" -> back to the menu -> quit.
	tt, buf := tuiWith(t, "list", "work", "gh", "q")
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

// --- the banner and the menu ------------------------------------------------

// The banner exists to answer "where is this about to write". Both locations are
// environment-overridable, so a session pointed at a sandbox and one pointed at
// the real tree are otherwise indistinguishable - and every entry under
// "Change ~/.ssh" rewrites whichever one it is.
func TestTheBannerNamesTheBinaryAndWhereItWillOperate(t *testing.T) {
	tt, buf := tuiWith(t, "q")
	tt.run()
	out := buf.String()

	for _, want := range []string{
		"sshmgr ",                  // which binary
		runtime.GOOS,               // and which build of it
		tt.p.ConfigDir,             // where state is read from
		tt.p.SSHDir,                // and where it will be written
		"1 profile, 1 host, 1 key", // what it found there, singular forms included
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the banner omits %q:\n%s", want, out)
		}
	}
}

// A first run has no manifest, which is the state most likely to send someone to
// the docs. The banner names the command that fixes it instead.
func TestTheBannerTellsAFirstRunWhatToDo(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	var buf bytes.Buffer
	tt := &tui{p: p, pr: &scriptPrompter{answers: []string{"q"}}, out: &buf}
	tt.run()

	out := buf.String()
	if !strings.Contains(out, "none yet") || !strings.Contains(out, "sshmgr init") {
		t.Errorf("a manifest-less banner should name the command that creates one:\n%s", out)
	}
	// Still a usable screen: the menu is drawn even with nothing to act on.
	if !strings.Contains(out, "Browse profiles & hosts") {
		t.Errorf("the menu should render without a manifest:\n%s", out)
	}
}

// Every problem row carries the command that resolves it, so the report and the
// remedy are never in two different places.
func TestAProblemRowCarriesItsFix(t *testing.T) {
	for _, tc := range []struct{ row, fix string }{
		{"drifted from the manifest", "sshmgr reconcile"},
		{"none yet", "sshmgr init"},
	} {
		r := bannerRow{label: "x", value: tc.row, fix: tc.fix}
		line := r.String()
		if !strings.HasPrefix(line, "!") {
			t.Errorf("a row with a fix should be marked: %q", line)
		}
		if !strings.Contains(line, tc.fix) {
			t.Errorf("row %q does not name its fix %q", line, tc.fix)
		}
	}
	// And a plain fact is not marked as a problem.
	if strings.HasPrefix(bannerRow{label: "ssh", value: "/home/x/.ssh"}.String(), "!") {
		t.Error("a row with no fix should not be marked as a problem")
	}
}

// Both halves of what the menu shows are accepted: the number in the left column
// and the verb in the right. Typing what is on screen should never be a dead end.
func TestANumberAndTheVerbSelectTheSameEntry(t *testing.T) {
	for i, m := range tuiMenu {
		byNumber, ok1 := lookupMenu(strconv.Itoa(i + 1))
		byVerb, ok2 := lookupMenu(m.verb)
		if !ok1 || !ok2 {
			t.Fatalf("%s: number=%v verb=%v", m.label, ok1, ok2)
		}
		if byNumber.handler != m.handler || byVerb.handler != m.handler {
			t.Errorf("%s: number gave %q, verb gave %q", m.label, byNumber.handler, byVerb.handler)
		}
	}
}

// An answer that is not a choice must not select one - the old failure mode was
// running whichever entry happened to be first.
func TestAnUnknownAnswerSelectsNothing(t *testing.T) {
	for _, answer := range []string{"", "0", "99", "-1", "reconcil", "  ", "1x"} {
		if _, ok := lookupMenu(answer); ok {
			t.Errorf("%q was treated as a selection", answer)
		}
	}
}

// ...and it re-prompts rather than ending the session, because a typo should not
// cost you the screen. A bare Enter redraws without comment.
func TestATypoRePromptsAndABlankLineIsSilent(t *testing.T) {
	tt, buf := tuiWith(t, "zzz", "", "q")
	tt.run()
	out := buf.String()

	if !strings.Contains(out, "not a choice: zzz") {
		t.Errorf("a typo should say so:\n%s", out)
	}
	if strings.Contains(out, "not a choice: \n") || strings.Contains(out, "not a choice:  ") {
		t.Errorf("a bare Enter should redraw silently:\n%s", out)
	}
	// Three menu draws: the first, one after the typo, one after the blank.
	if n := strings.Count(out, "  Inspect\n"); n != 3 {
		t.Errorf("menu drawn %d times, want 3 (initial + two re-prompts):\n%s", n, out)
	}
}

// Every entry must sit in a group that is actually drawn. A mistyped group name
// removes its entries from the screen while leaving them selectable by number -
// a silent failure, since nothing else would notice.
func TestEveryMenuEntryIsDrawnInSomeGroup(t *testing.T) {
	tt, buf := tuiWith(t, "q")
	tt.run()
	out := buf.String()

	drawn := map[string]bool{}
	for _, g := range menuGroups {
		drawn[g] = true
	}
	for _, m := range tuiMenu {
		if !drawn[m.group] {
			t.Errorf("%q is in group %q, which menuGroups does not draw", m.label, m.group)
		}
		if !strings.Contains(out, m.label) {
			t.Errorf("%q never appears on the menu", m.label)
		}
	}
	for _, g := range menuGroups {
		if !strings.Contains(out, "  "+g) {
			t.Errorf("group %q is declared but has no entries on screen", g)
		}
	}
}

// The screen is piped into files and diffs, so no line may end in whitespace.
// The padded columns make this easy to get wrong: %-*s on a final column leaves
// the padding behind.
func TestTheScreenHasNoTrailingWhitespace(t *testing.T) {
	tt, buf := tuiWith(t, "q")
	tt.run()
	for i, line := range strings.Split(buf.String(), "\n") {
		if line != strings.TrimRight(line, " \t") {
			t.Errorf("line %d ends in whitespace: %q", i+1, line)
		}
	}
}
