//go:build !windows

package perms

import "os"

// SetPerms applies a POSIX mode. Mirrors platforms/{macos,linux}.set_perms.
func SetPerms(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
