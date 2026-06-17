//go:build !windows

package perms

import "os"

// SetPerms applies a POSIX mode. Mirrors platforms/{macos,linux}.set_perms.
func SetPerms(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// PermsOK reports whether path already has exactly the expected low-9-bit mode.
// Mirrors platforms.base.perms_ok ((st_mode & 0o777) == mode).
func PermsOK(path string, mode os.FileMode) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Perm() == mode.Perm()
}
