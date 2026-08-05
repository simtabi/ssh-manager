package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// The mutation guard must be re-entrant within a process. flock is per file
// descriptor and Acquire blocks until the lock is free, so taking it a second
// time meant waiting forever on a lock this same process already held - and
// since the guard prints nothing, the symptom was the TUI freezing with no
// output on the second action of a session.
func TestMutationGuardDoesNotDeadlockOnItself(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	// Package state: another test in this binary may already hold it. Closing
	// the fd matters, not just clearing the variable - see releaseHeldLock.
	releaseHeldLock(t)
	if heldLock != nil {
		heldLock()
		heldLock = nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ { // reconcile, then pin, then rotate
			snapshotBeforeMutation(p)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the mutation guard blocked on a lock this process already holds")
	}
	if heldLock == nil {
		t.Error("the guard should be holding the lock after running")
	}
}
