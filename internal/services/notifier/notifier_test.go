package notifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func ptr(s string) *string { return &s }

func setup(t *testing.T, desktopNotify bool) (*Notifier, paths.Paths) {
	t.Helper()
	cfg := t.TempDir()
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: cfg}
	mj := `{"version":1,"defaults":{"warn_before_days":[30],
	  "expiry_check":{"enabled":true,"debounce_hours":24,"desktop_notify":` +
		map[bool]string{true: "true", false: "false"}[desktopNotify] + `}},"profiles":{}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	return New(p, &m), p
}

func TestStatesFromInventory(t *testing.T) {
	n, p := setup(t, false)
	inv := inventory.New()
	inv.Record("SHA256:overdue", inventory.KeyRecord{
		Profile: "w", Path: "~/.ssh/profiles/w/k", Type: "ed25519",
		RotateAfterDays: 365, ExpiresOn: ptr("2020-01-01"),
	})
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	states, err := n.States(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State != "overdue" {
		t.Fatalf("states=%+v want one overdue", states)
	}
}

func TestNotifyGating(t *testing.T) {
	// desktop_notify disabled -> Notify returns false before touching a backend,
	// even with an attention-worthy key and force.
	n, p := setup(t, false)
	inv := inventory.New()
	inv.Record("SHA256:x", inventory.KeyRecord{
		Profile: "w", Path: "~/.ssh/profiles/w/k", Type: "ed25519",
		RotateAfterDays: 365, ExpiresOn: ptr("2020-01-01"),
	})
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	if n.Notify(time.Now(), true) {
		t.Error("desktop_notify=false should gate the alert to false")
	}

	// No keys at all -> no attention -> false.
	n2, p2 := setup(t, true)
	if err := inventory.New().Save(p2.Inventory()); err != nil {
		t.Fatal(err)
	}
	if n2.Notify(time.Now(), true) {
		t.Error("empty inventory should not fire a notification")
	}
}

// The daily alert is the one surface that reaches a user who is not running
// sshmgr right now, and a dangling key is the class of problem it could not
// previously tell them about.
func TestNotifyCoversDanglingKeys(t *testing.T) {
	cfg := t.TempDir()
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}
	mj := `{"version":1,"defaults":{"warn_before_days":[30],
	  "expiry_check":{"enabled":true,"debounce_hours":24,"desktop_notify":true}},
	  "profiles":{"work":{"key_scope":"per_service","keys":[{"name":"work_spare-ed25519"}],
	    "hosts":[{"alias":"gh","hostname":"github.com","user":"git","key_name":"work_gh-ed25519"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	n := New(p, &m)

	// Nothing expiring, but a declared key no host uses.
	dangling := n.Dangling()
	if len(dangling) != 1 || dangling[0].Subject != "work/work_spare-ed25519" {
		t.Fatalf("dangling = %+v, want the unwired declared key", dangling)
	}

	// Non-blocking states stay out of the alert: an unminted key is ordinary.
	for _, f := range dangling {
		if f.State == "missing" {
			t.Error("an unminted key should not reach the desktop alert")
		}
	}

	// With no manifest there is nothing to audit against, and that is not an error.
	if got := New(p, nil).Dangling(); got != nil {
		t.Errorf("no manifest should mean no findings, got %+v", got)
	}
}

// What this asserts is the decision, not the cadence: a manifest with nothing
// blocking has nothing to say, and an unwired declared key is something to say.
// The cadence itself is covered by TestADeliveredNotificationMarksAndThenGatesTheCadence.
func TestACleanTreeFiresNothingButAnUnwiredKeyIsFound(t *testing.T) {
	cfg := t.TempDir()
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}
	mj := `{"version":1,"defaults":{"warn_before_days":[30],
	  "expiry_check":{"enabled":true,"debounce_hours":24,"desktop_notify":true}},
	  "profiles":{"work":{"key_scope":"per_service","keys":[{"name":"work_spare-ed25519"}],
	    "hosts":[]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	n := New(p, &m)
	now := time.Now()

	// Nothing at all to say when the manifest is clean of blocking states.
	empty := New(p, &manifest.Manifest{Defaults: m.Defaults})
	if empty.Notify(now, true) {
		t.Error("a clean tree should fire nothing")
	}
	// With a dangling key there is something to say; whether a desktop backend
	// exists is the platform's business, so only the decision to try is asserted.
	if len(n.Dangling()) == 0 {
		t.Fatal("expected the unwired key to be found")
	}
}

// stubBackend puts a fake notification backend first on PATH and returns the
// file it records its arguments in. desktop.Notify picks a backend with
// exec.LookPath, so this makes the delivery decision deterministic instead of
// depending on whether the machine running the tests happens to have one.
func stubBackend(t *testing.T) string {
	t.Helper()
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "terminal-notifier"
	case "linux":
		name = "notify-send"
	default:
		t.Skip("no scriptable backend to stand in for on " + runtime.GOOS)
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "calls.txt")
	// Builtins only: PATH is rewritten below, so nothing external is reachable.
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + record + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return record
}

// noBackend makes every lookup fail, which is the state on a headless box.
func noBackend(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func overdueInventory(t *testing.T, p paths.Paths) {
	t.Helper()
	inv := inventory.New()
	inv.Record("SHA256:overdue", inventory.KeyRecord{
		Profile: "w", Path: "~/.ssh/profiles/w/k", Type: "ed25519",
		RotateAfterDays: 365, ExpiresOn: ptr("2020-01-01"),
	})
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
}

// The cadence cache is only allowed to advance when a notification was actually
// delivered. Marking it on a failed send means the user is told nothing and then
// not told again until the interval elapses - the one failure mode where a
// silent tool looks exactly like a healthy one.
func TestAFailedSendDoesNotConsumeTheCadence(t *testing.T) {
	noBackend(t)
	n, p := setup(t, true)
	overdueInventory(t, p)

	if n.Notify(time.Now(), true) {
		t.Error("Notify should report false when no backend handled it")
	}
	if _, err := os.Stat(p.NotifyCache()); err == nil {
		t.Fatal("a send that never reached the user marked the cadence as spent")
	}
}

func TestADeliveredNotificationMarksAndThenGatesTheCadence(t *testing.T) {
	record := stubBackend(t)
	n, p := setup(t, true)
	overdueInventory(t, p)
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	if !n.Notify(now, false) {
		t.Fatal("an overdue key with a working backend should notify")
	}
	body, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the backend was not invoked: %v", err)
	}
	if !strings.Contains(string(body), "rotation") {
		t.Errorf("notification body = %q, want the rotation title", body)
	}
	stamp := parseT(n.read(p.NotifyCache())["notified"])
	if !stamp.Equal(now) {
		t.Errorf("cache holds %v, want the time of the send (%v)", stamp, now)
	}

	// Overdue keys are the daily cadence, so an hour later is still gated.
	if n.Notify(now.Add(time.Hour), false) {
		t.Error("a second notification inside the interval should be suppressed")
	}
	// ...and --force overrides the gate, which is what makes `notify --force`
	// usable for checking the wiring without waiting a day.
	if !n.Notify(now.Add(time.Hour), true) {
		t.Error("--force should fire regardless of the cadence")
	}
	// Past the interval it fires on its own again.
	if !n.Notify(now.Add(25*time.Hour), false) {
		t.Error("past the daily interval the alert should fire again")
	}
}

// The notify cache may have been written by the Python version, whose
// datetime.isoformat() output carries no timezone. Failing to parse it reads as
// "never notified", so the first Go run would re-alert about keys the user was
// told about hours earlier - and every run after a fresh install would too.
func TestTheCacheStampParsesEveryFormatItWasEverWrittenIn(t *testing.T) {
	want := time.Date(2026, 3, 1, 9, 30, 15, 0, time.UTC)
	for _, s := range []string{
		"2026-03-01T09:30:15Z",        // RFC3339, what Go writes
		"2026-03-01T09:30:15.000000Z", // RFC3339 with microseconds
		"2026-03-01T09:30:15",         // Python isoformat(), no zone
		"2026-03-01T09:30:15.000000",  // Python isoformat() with microseconds
	} {
		got := parseT(s)
		if got.IsZero() {
			t.Errorf("parseT(%q) failed; a stale cache reads as never-notified", s)
			continue
		}
		if !got.UTC().Equal(want) {
			t.Errorf("parseT(%q) = %v, want %v", s, got.UTC(), want)
		}
	}
	// Anything else is treated as absent rather than guessed at.
	for _, bad := range []any{nil, "", "not a date", 42, map[string]any{}} {
		if !parseT(bad).IsZero() {
			t.Errorf("parseT(%v) should be the zero time", bad)
		}
	}
}

// The alert has to fit in a desktop notification, so both lists are truncated -
// but a truncated dangling list says how many were left out. Being told about
// three of nine broken keys without being told there are nine is worse than
// useless: it looks like the whole story.
func TestALongDanglingListSaysHowManyItLeftOut(t *testing.T) {
	record := stubBackend(t)
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	keys := ""
	for i := range 9 {
		if i > 0 {
			keys += ","
		}
		keys += fmt.Sprintf(`{"name":"work_spare%d-ed25519"}`, i)
	}
	mj := `{"version":1,"defaults":{"warn_before_days":[30],
	  "expiry_check":{"enabled":true,"debounce_hours":24,"desktop_notify":true}},
	  "profiles":{"work":{"key_scope":"per_service","keys":[` + keys + `],"hosts":[]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	n := New(p, &m)
	if got := len(n.Dangling()); got != 9 {
		t.Fatalf("Dangling found %d, want 9 unwired declared keys", got)
	}

	if !n.Notify(time.Now(), true) {
		t.Fatal("nine dangling keys should notify")
	}
	body, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the backend was not invoked: %v", err)
	}
	// Three named, then a count of the rest - not silent truncation.
	if !strings.Contains(string(body), "+6 more dangling") {
		t.Errorf("body = %q, want the remaining six accounted for", body)
	}
	if !strings.Contains(string(body), "dangling keys") {
		t.Errorf("title = %q, want the dangling-only title when nothing is expiring", body)
	}
}
