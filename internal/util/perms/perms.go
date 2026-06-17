// Package perms centralizes the file modes ssh-manager enforces and applies them
// in a platform-correct way - POSIX chmod on Unix, ACLs via icacls on Windows.
// Ported from util/perms.py + the platforms/*.set_perms layer.
package perms

import "os"

// Modes SSH expects. Private keys and configs must not be group/other readable;
// dirs are 0700; host public keys are world-readable.
const (
	DirMode        os.FileMode = 0o700
	PrivateKeyMode os.FileMode = 0o600
	ConfigMode     os.FileMode = 0o600
	PublicKeyMode  os.FileMode = 0o644
)
