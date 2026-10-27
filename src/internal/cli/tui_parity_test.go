package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
)

// The TUI's Change entries each have a CLI command beside them, and the menu
// promises they ask before they write. These tests hold the TUI to the guards
// the CLI applies, because every one of them had drifted: Pin wrote without
// asking, Deploy neither asked nor snapshotted, Rotate skipped the key backup
// the CLI treats as a hard stop, and Reconcile read state before it locked.

func declining(tt *tui) *tui {
	tt.pr.(*scriptPrompter).confirm = false
	return tt
}

func accepting(tt *tui) *tui {
	tt.pr.(*scriptPrompter).confirm = true
	return tt
}

func onlyKey(t *testing.T, tt *tui) string {
	t.Helper()
	keys := keyNames(tt.manifest())
	if len(keys) == 0 {
		t.Fatal("the fixture manifest declares no key")
	}
	return keys[0]
}

func noSnapshots(t *testing.T, tt *tui, what string) {
	t.Helper()
	if got := snapshots.List(tt.p.SnapshotsDir()); len(got) != 0 {
		t.Errorf("%s: declining still wrote %d snapshot(s): %v", what, len(got), got)
	}
}

func TestTuiPinAsksBeforeItWrites(t *testing.T) {
	releaseHeldLock(t)
	tt, buf := tuiWith(t, "6", "q") // by number: this test is about the prompt, not the label
	declining(tt).run()
	noSnapshots(t, tt, "pin")
	// Not "pinned": the banner's own "0 of 1 pinned" row contains it.
	if !strings.Contains(buf.String(), "cancelled") {
		t.Errorf("a declined pin should say it was cancelled:\n%s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(tt.p.SSHDir, "known_hosts")); err == nil {
		t.Error("pin wrote known_hosts although it was declined")
	}
}

// The entry used to be listed as `knownhosts pin`, which is what people have
// learned to type. It runs `knownhosts init --all`, so that is what the menu now
// shows, but the old answer still selects it.
func TestTuiPinStillAnswersToItsOldName(t *testing.T) {
	for _, answer := range []string{"knownhosts init --all", "knownhosts pin"} {
		item, ok := lookupMenu(answer)
		if !ok || item.handler != "knownhosts" {
			t.Errorf("%q should select the known_hosts entry, got %+v (found=%v)", answer, item, ok)
		}
	}
}

func TestTuiDeployAsksBeforeItWrites(t *testing.T) {
	releaseHeldLock(t)
	tt, buf := tuiWith(t)
	tt.pr.(*scriptPrompter).answers = []string{"deploy", onlyKey(t, tt), "q"}
	declining(tt).run()
	noSnapshots(t, tt, "deploy")
	if !strings.Contains(buf.String(), "cancelled") {
		t.Errorf("a declined deploy should say it was cancelled:\n%s", buf.String())
	}
}

// Rotating archives the key being replaced and discards the one before it, so
// the CLI refuses to start without an encrypted backup. The TUI rotated anyway.
func TestTuiRotateRefusesWithoutAKeyBackup(t *testing.T) {
	releaseHeldLock(t)
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	tt, buf := tuiWith(t)
	tt.pr.(*scriptPrompter).answers = []string{"rotate", onlyKey(t, tt), "q"}
	accepting(tt).run()
	out := buf.String()
	if !strings.Contains(out, "SSH_MANAGER_AGE_RECIPIENT") {
		t.Errorf("rotate should stop and name the missing backup recipient:\n%s", out)
	}
	noSnapshots(t, tt, "rotate without a backup")
}

// A mutating command takes the lock before it reads the manifest or inventory,
// or it can save a stale copy over whatever the command it waited for wrote.
// The TUI's Reconcile read both first.
func TestTuiReconcileLocksBeforeItReads(t *testing.T) {
	releaseHeldLock(t)
	mutation.Release()
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	tt, _ := tuiWith(t, "reconcile", "q")
	declining(tt).run()
	if !mutation.Held() {
		t.Error("reconcile read the manifest without taking the lock")
	}
	noSnapshots(t, tt, "reconcile")
}
