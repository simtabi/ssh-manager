package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
)

// RestoreByIDIn leaves the lock to its caller (services/snapshots), and restore
// and prune both rewrite what other commands read, so the CLI has to take it.
// Neither did, which let a restore interleave with a reconcile.

func freshLock(t *testing.T) {
	t.Helper()
	mutation.Release()
}

func TestSnapshotsPruneTakesTheLock(t *testing.T) {
	editHome(t)
	freshLock(t)
	run(t, "snapshots", "prune")
	if !mutation.Held() {
		t.Error("snapshots prune deleted snapshots without taking the lock")
	}
}

func TestSnapshotsRestoreTakesTheLock(t *testing.T) {
	p := editHome(t)
	if err := os.MkdirAll(p.SSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.SSHDir, "config"), []byte("Host x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), 10, ""); err != nil {
		t.Fatal(err)
	}
	freshLock(t)
	if out, err := runIn(t, "", "snapshots", "restore", "--yes"); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if !mutation.Held() {
		t.Error("snapshots restore rewrote ~/.ssh without taking the lock")
	}
}

func TestTuiSnapshotRestoreTakesTheLock(t *testing.T) {
	releaseHeldLock(t)
	freshLock(t)
	tt, _ := tuiWith(t)
	if err := os.MkdirAll(tt.p.SSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tt.p.SSHDir, "config"), []byte("Host x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshots.Snapshot(tt.p.SSHDir, tt.p.SnapshotsDir(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	tt.pr.(*scriptPrompter).answers = []string{"snapshots", filepath.Base(snap), "q"}
	accepting(tt).run()
	if !mutation.Held() {
		t.Error("the TUI restored a snapshot without taking the lock")
	}
}
