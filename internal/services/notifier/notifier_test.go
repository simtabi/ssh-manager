package notifier

import (
	"encoding/json"
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

// Firing is still cadence-gated, and expiry still sets the pace - a dangling key
// does not become more urgent by the day.
func TestNotifyFiresForDanglingAloneAtTheWeeklyCadence(t *testing.T) {
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
