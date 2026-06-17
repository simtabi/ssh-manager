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
	return New(p, m.Defaults), p
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
	inv.Save(p.Inventory())
	if n.Notify(time.Now(), true) {
		t.Error("desktop_notify=false should gate the alert to false")
	}

	// No keys at all -> no attention -> false.
	n2, p2 := setup(t, true)
	inventory.New().Save(p2.Inventory())
	if n2.Notify(time.Now(), true) {
		t.Error("empty inventory should not fire a notification")
	}
}
