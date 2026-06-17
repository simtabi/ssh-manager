//go:build windows

package perms

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// broadPrincipals are the over-broad ACEs we strip from keys/dirs/configs so no
// other principal retains access. Mirrors platforms/windows._BROAD_PRINCIPALS.
var broadPrincipals = []string{"Everyone", "Authenticated Users", "Users", `BUILTIN\Users`}

// SetPerms restricts path to the current user (the Windows ACL equivalent of
// 600/700): drop inherited ACEs, grant only this user, strip broad grants. The
// POSIX mode is advisory on Windows. Mirrors platforms/windows.set_perms.
func SetPerms(path string, _ os.FileMode) error {
	if _, err := exec.LookPath("icacls"); err != nil {
		return fmt.Errorf("icacls not found: icacls ships with Windows; ensure it's on PATH")
	}
	u := os.Getenv("USERNAME")
	if u == "" {
		if cu, err := user.Current(); err == nil {
			u = cu.Username
		}
	}
	if err := exec.Command("icacls", path, "/inheritance:r").Run(); err != nil {
		return fmt.Errorf("icacls /inheritance:r failed for %s: %w", path, err)
	}
	if err := exec.Command("icacls", path, "/grant:r", u+":F").Run(); err != nil {
		return fmt.Errorf("icacls /grant:r failed for %s: %w", path, err)
	}
	for _, p := range broadPrincipals {
		// Removing an ACE that isn't present is a harmless no-op.
		_ = exec.Command("icacls", path, "/remove:g", p).Run()
	}
	return nil
}
