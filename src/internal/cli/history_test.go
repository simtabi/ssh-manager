package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

func historyOps(t *testing.T, p paths.Paths, f history.Filter) []history.Op {
	t.Helper()
	s, err := history.Open(p.HistoryDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ops, err := s.Query(f)
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

func liveOps(t *testing.T, p paths.Paths) []history.Op {
	t.Helper()
	var out []history.Op
	for _, o := range historyOps(t, p, history.Filter{}) {
		if o.Source != history.SourceBackfill {
			out = append(out, o)
		}
	}
	return out
}

// Every command that changes something is recorded with no code of its own:
// the guard opens the operation, and the audit events it raises land in it.
func TestAMutatingCommandIsRecordedWithItsEventsAndManifest(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	ops := liveOps(t, p)
	if len(ops) != 2 {
		t.Fatalf("recorded %d operations, want 2: %+v", len(ops), ops)
	}
	hostAdd := ops[0]
	if hostAdd.Command != "host add" || hostAdd.Source != history.SourceCLI || hostAdd.Result != history.ResultOK {
		t.Errorf("newest = %s/%s/%s, want host add/cli/ok", hostAdd.Command, hostAdd.Source, hostAdd.Result)
	}
	if strings.Join(hostAdd.Args, " ") != "work gh --hostname=github.com --user=git" {
		t.Errorf("args = %q", hostAdd.Args)
	}
	if len(hostAdd.Events) == 0 || hostAdd.Events[0].Event != "host.add" {
		t.Errorf("events = %+v, want the host.add audit event", hostAdd.Events)
	}
	if hostAdd.ManifestBefore == "" || hostAdd.ManifestAfter == "" || hostAdd.ManifestBefore == hostAdd.ManifestAfter {
		t.Errorf("manifest before %q after %q: an edit should change it", hostAdd.ManifestBefore, hostAdd.ManifestAfter)
	}
	if got := historyOps(t, p, history.Filter{Host: "gh"}); len(got) != 1 {
		t.Errorf("--host gh found %d operations, want 1", len(got))
	}
}

func TestAReadOnlyCommandRecordsNothing(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	before := len(liveOps(t, p))
	run(t, "list")
	run(t, "validate")
	run(t, "history")
	if after := len(liveOps(t, p)); after != before {
		t.Errorf("read-only commands added %d operation(s)", after-before)
	}
}

// A "no" before the lock changed nothing and held nothing, so it is not an
// operation. A "no" after the lock - the commands that still ask while holding
// it - is one, and ends aborted.
func TestADeclineIsRecordedOnlyOnceTheCommandHeldTheLock(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	before := len(liveOps(t, p))
	if _, err := runIn(t, "n\n", "host", "delete", "work", "gh"); err == nil {
		t.Skip("host delete did not ask here")
	}
	if got := len(liveOps(t, p)); got != before {
		t.Errorf("a decline before the lock recorded %d operation(s)", got-before)
	}

	mutation.Begin(mutation.Scope{Command: "rotate", Source: history.SourceCLI})
	lockForMutation(p)
	mutation.End(mutation.Outcome{Err: errAborted, Aborted: true})
	if ops := liveOps(t, p); ops[0].Command != "rotate" || ops[0].Result != history.ResultAborted {
		t.Errorf("newest = %s/%s, want rotate/aborted", ops[0].Command, ops[0].Result)
	}
}

// Values that are not manifest names are never written to the history.
func TestArgsKeepNamesAndRedactEverythingElse(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"bundle", "--recipient", "age1abc", "--output", "/secret/place"})
	c, _, err := root.Find([]string{"bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ParseFlags([]string{"--recipient", "age1abc", "--output", "/secret/place"}); err != nil {
		t.Fatal(err)
	}
	s := scopeFor(c, nil)
	joined := strings.Join(s.Args, " ")
	if strings.Contains(joined, "age1abc") || strings.Contains(joined, "/secret/place") {
		t.Errorf("args leaked a value: %s", joined)
	}
	if !strings.Contains(joined, "--recipient=<set>") {
		t.Errorf("a redacted flag should still say it was set: %s", joined)
	}
}

func TestPositionalArgumentsBecomeSubjects(t *testing.T) {
	got := positionalSubjects("deploy", []string{"work/id_work", "web1"})
	want := []history.Subject{{Kind: "profile", Name: "work"}, {Kind: "key", Name: "id_work"}, {Kind: "target", Name: "web1"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("subject %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestHistoryListsShowsAndEmitsJSON(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	out := run(t, "history", "--source", "cli")
	if !strings.Contains(out, "host add") || !strings.Contains(out, "profile add") {
		t.Errorf("history did not list both operations:\n%s", out)
	}

	js := run(t, "history", "--json", "--command", "host")
	var lines []history.Op
	for _, line := range strings.Split(strings.TrimSpace(js), "\n") {
		var o history.Op
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			t.Fatalf("not one JSON object per line: %v\n%s", err, js)
		}
		lines = append(lines, o)
	}
	if len(lines) != 1 || lines[0].Command != "host add" || len(lines[0].Events) == 0 {
		t.Fatalf("--json --command host = %+v", lines)
	}

	show := run(t, "history", "show", lines[0].OpID[:8])
	for _, want := range []string{"host add", "host.add", "--- manifest before", "+++ manifest after", `"gh"`} {
		if !strings.Contains(show, want) {
			t.Errorf("history show is missing %q:\n%s", want, show)
		}
	}
	_ = p
}

// The TUI is one process making several changes; each is its own operation.
func TestEachTuiChangeIsItsOwnOperation(t *testing.T) {
	releaseHeldLock(t)
	tt, _ := tuiWith(t)
	tt.pr.(*scriptPrompter).answers = []string{"reconcile", "snapshots", "", "q"}
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	accepting(tt).run()
	var tui []history.Op
	for _, o := range liveOps(t, tt.p) {
		if o.Source == history.SourceTUI {
			tui = append(tui, o)
		}
	}
	if len(tui) == 0 || tui[len(tui)-1].Command != "reconcile" {
		t.Fatalf("TUI operations = %+v, want reconcile recorded on its own", tui)
	}
}

// audit.log is still the record; the store indexes it and must not change it.
func TestAuditLogIsWrittenAsBefore(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	b, err := os.ReadFile(p.AuditLog())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	last := lines[len(lines)-1]
	a, ok := history.ParseAuditLine(last)
	if !ok || a.Event != "profile.add" {
		t.Fatalf("last audit line %s", last)
	}
	if !bytes.HasPrefix(last, []byte(`{"ts":"`)) || !bytes.Contains(last, []byte(`,"event":"profile.add","profile":"work"}`)) {
		t.Errorf("audit line changed shape: %s", last)
	}
}

func TestScopedReleasesTheLockWhenItReturns(t *testing.T) {
	p := editHome(t)
	mutation.Release()
	err := mutation.Scoped(p, mutation.Scope{Command: "web test", Source: history.SourceWeb}, func() error {
		if !mutation.Held() {
			t.Error("the lock is not held inside the scope")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Held() {
		t.Error("Scoped kept the lock after returning; a server would block every CLI command")
	}
	ops := historyOps(t, p, history.Filter{Source: history.SourceWeb})
	if len(ops) != 1 || ops[0].Result != history.ResultOK {
		t.Errorf("the scoped run was recorded as %+v", ops)
	}
}
