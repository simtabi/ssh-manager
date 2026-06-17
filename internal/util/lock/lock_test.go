package lock

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
