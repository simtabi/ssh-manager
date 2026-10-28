// Package mutation is the guard every command that changes state goes
// through: the advisory lock that serializes sshmgr processes, the crash-residue
// sweep, and the ~/.ssh snapshot that makes the change reversible.
//
// It moved here from the command layer so that something other than the CLI -
// the web server - can guard its changes the same way.
package mutation

import (
	"errors"
	"fmt"
	"os"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/lock"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// heldLock keeps the acquired advisory lock alive for the rest of the process so
// the OS doesn't release it (and GC doesn't close the fd) before the mutation
// finishes; a short-lived CLI command releases it on exit.
var heldLock func()

// SnapshotBeforeMutation is the native mutation guard (mirrors the Facade's
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
func SnapshotBeforeMutation(p paths.Paths, retain int) string {
	LockForMutation(p)
	snapshots.CleanTempArtifacts(p.SSHDir)
	snap, err := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), retain, "")
	recordSnapshot(snap, err)
	return snap
}

// LockForMutation takes the advisory lock, once per process. A mutating
// command calls it before it reads the manifest or inventory, not just before
// it writes: one that loaded state first and then waited for the lock saved
// that stale copy afterwards, silently dropping whatever the command it waited
// for had written. SnapshotBeforeMutation calls it too, so a command that
// forgets still holds the lock while it mutates.
func LockForMutation(p paths.Paths) {
	if heldLock == nil {
		rel, err := lock.Acquire(p.LockFile())
		if err != nil {
			// Best-effort stays best-effort - refusing to work because a lock file
			// cannot be made would strand the user on a read-only or exotic
			// filesystem - but not silent. Acquire blocks while another process
			// holds the lock, so an error here means the lock itself is broken,
			// and the serialization the guard promises is simply not happening.
			_, _ = fmt.Fprintf(os.Stderr, "sshmgr: WARNING: could not take the advisory lock at %s, "+
				"so a concurrent sshmgr command could interleave with this one: %v\n", p.LockFile(), err)
		} else {
			heldLock = rel
		}
	}
	opening(p)
}

// Held reports whether this process holds the advisory lock.
func Held() bool { return heldLock != nil }

// Release gives up the lock this process holds, if any. A CLI command never
// needs to - exiting releases it - but a test that runs many commands in one
// process does, and so does a long-lived server between operations.
func Release() {
	if heldLock != nil {
		heldLock()
		heldLock = nil
	}
}

// Scoped runs fn as one operation under the lock and releases the lock when fn
// returns. It is for a long-lived process: a CLI command holds the lock until
// it exits, which a server cannot do without blocking every other sshmgr
// command for as long as it runs. fn must not call Scoped itself.
func Scoped(p paths.Paths, s Scope, fn func() error) error {
	// The CLI installs the sink at start-up; a caller that is not the CLI may
	// not have, and its events would reach audit.log and miss the history.
	InstallSink()
	Begin(s)
	LockForMutation(p)
	err := fn()
	End(Outcome{Err: err, Aborted: errors.Is(err, ErrDeclined)})
	Release()
	return err
}
