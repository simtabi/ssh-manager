package lock

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestAcquireReleaseReacquire(t *testing.T) {
	lp := filepath.Join(t.TempDir(), ".state", ".lock")

	rel, err := Acquire(lp)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := os.Stat(lp); err != nil {
		t.Errorf("lock file not created: %v", err)
	}
	rel() // release

	// A second acquire after release must succeed (lock is free again).
	rel2, err := Acquire(lp)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	rel2()

	// The parent dir is owner-only (POSIX; Windows uses ACLs, not Unix mode bits).
	if runtime.GOOS == "windows" {
		return
	}
	if fi, err := os.Stat(filepath.Dir(lp)); err == nil && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("lock dir should be 0700, got %o", fi.Mode().Perm())
	}
}

// The lock's whole purpose is mutual exclusion between processes: a scheduled
// `audit --notify` firing while the user is halfway through a `reconcile` is the
// case it exists for. Acquire/release in one goroutine proves nothing about
// that, so this re-executes the test binary as a second process and checks it
// waits.
func TestASecondProcessWaitsForTheLock(t *testing.T) {
	lp := filepath.Join(t.TempDir(), ".state", ".lock")
	rel, err := Acquire(lp)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	done := filepath.Join(filepath.Dir(lp), "child-got-it")
	child := exec.Command(os.Args[0], "-test.run=^TestLockChildProcess$", "-test.v")
	child.Env = append(os.Environ(), "SSHMGR_LOCK_CHILD=1", "SSHMGR_LOCK_PATH="+lp, "SSHMGR_LOCK_DONE="+done)
	if err := child.Start(); err != nil {
		t.Fatalf("starting the second process: %v", err)
	}
	t.Cleanup(func() { _ = child.Wait() })

	// It must still be waiting while we hold it. A generous window, since the
	// failure this guards against is the child acquiring immediately.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(done); err == nil {
			rel()
			t.Fatal("a second process acquired the lock while it was held")
		}
		time.Sleep(20 * time.Millisecond)
	}

	rel()

	// Released, so it must get through now.
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(done); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the second process never acquired the lock after it was released")
}

// TestLockChildProcess is the second process for the test above. It is inert
// unless the parent asked for it.
func TestLockChildProcess(t *testing.T) {
	if os.Getenv("SSHMGR_LOCK_CHILD") != "1" {
		t.Skip("helper process; driven by TestASecondProcessWaitsForTheLock")
	}
	rel, err := Acquire(os.Getenv("SSHMGR_LOCK_PATH"))
	if err != nil {
		t.Fatalf("child acquire: %v", err)
	}
	defer rel()
	if err := os.WriteFile(os.Getenv("SSHMGR_LOCK_DONE"), []byte("got it\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The lock is not re-entrant, and that is worth pinning rather than discovering:
// a second Acquire inside one process blocks exactly as another process would,
// because each call opens its own descriptor. A command that took the lock and
// then called something that took it again froze with no output and no timeout,
// which is what happened to the TUI on the second mutating action of a session.
func TestASecondAcquireInOneProcessBlocksToo(t *testing.T) {
	lp := filepath.Join(t.TempDir(), ".state", ".lock")
	rel, err := Acquire(lp)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	got := make(chan func(), 1)
	go func() {
		r, err := Acquire(lp)
		if err != nil {
			close(got)
			return
		}
		got <- r
	}()

	select {
	case r := <-got:
		if r != nil {
			r()
		}
		rel()
		t.Fatal("the lock let one process take it twice; callers must not nest Acquire")
	case <-time.After(500 * time.Millisecond):
	}

	rel()
	select {
	case r := <-got:
		if r == nil {
			t.Fatal("the waiting acquire failed rather than succeeding once free")
		}
		r()
	case <-time.After(20 * time.Second):
		t.Fatal("the waiting acquire never completed after release")
	}
}
