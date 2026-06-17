//go:build !windows

package lock

import (
	"os"
	"path/filepath"
	"syscall"
)

// Acquire takes an exclusive advisory lock on lockPath (blocking until free) and
// returns a release func. Mirrors advisory_lock's POSIX fcntl/flock path.
func Acquire(lockPath string) (func(), error) {
	if err := secureMkdir(filepath.Dir(lockPath)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
