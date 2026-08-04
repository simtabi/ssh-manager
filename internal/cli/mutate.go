package cli

import (
	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/lock"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// heldLock keeps the acquired advisory lock alive for the rest of the process so
// the OS doesn't release it (and GC doesn't close the fd) before the mutation
// finishes; a short-lived CLI command releases it on exit.
var heldLock func()

// snapshotBeforeMutation is the native mutation guard (mirrors the Facade's
// _mutating): take the advisory lock so concurrent commands serialize, sweep crash
// residue, then snapshot ~/.ssh so the change is reversible. The lock is best-
// effort - a failure to acquire doesn't block the operation. Returns the snapshot
// path ("" if none was made).
//
// The lock is taken once per process, not once per call. flock is per open file
// descriptor, and Acquire blocks until it is free, so a second call in the same
// process waits forever on a lock that same process is holding - a deadlock with
// no output at all. One CLI command mutates once and exits, which is why this
// went unnoticed; the TUI is one process that mutates repeatedly (reconcile,
// then pin, then rotate) and hangs on the second action. Nothing is given up by
// holding it: the lock exists to serialize separate processes, and within one
// process these run in sequence anyway.
func snapshotBeforeMutation(p paths.Paths) string {
	if heldLock == nil {
		if rel, err := lock.Acquire(p.LockFile()); err == nil {
			heldLock = rel
		}
	}
	snapshots.CleanTempArtifacts(p.SSHDir)
	snap, _ := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), snapshotRetain(), "")
	return snap
}
