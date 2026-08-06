// Package lock is an advisory file lock so concurrent commands (e.g. a scheduled
// `audit --notify` and a manual `reconcile`) can't corrupt state mid-mutation.
// Ported from util/lock.py: an exclusive flock on POSIX, an exclusive-share
// CreateFile (with retry) on Windows. stdlib only.
package lock

import "os"

// secureMkdir creates dir (and parents) restricted to the owner (0700) - it holds
// the lock + caches that sit beside secrets.
func secureMkdir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700) // no-op on Windows ACL filesystems
	return nil
}
