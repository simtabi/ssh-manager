//go:build windows

package lock

import (
	"path/filepath"
	"syscall"
	"time"
)

// Acquire takes an advisory lock on lockPath by opening it with an exclusive share
// mode (a second holder gets a sharing violation), retrying briefly so a concurrent
// command waits rather than fails outright. Mirrors advisory_lock's msvcrt path.
func Acquire(lockPath string) (func(), error) {
	if err := secureMkdir(filepath.Dir(lockPath)); err != nil {
		return nil, err
	}
	ptr, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		h, err := syscall.CreateFile(ptr,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			0, // no sharing -> exclusive
			nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			return func() { _ = syscall.CloseHandle(h) }, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}
