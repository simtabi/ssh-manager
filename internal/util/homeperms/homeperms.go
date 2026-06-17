// Package homeperms is the single enumeration of the config-home secret paths and
// their canonical modes, shared by init (the seeder) and doctor (the fixer) so
// they can never disagree. Mirrors facade._secret_perms + SECRET_DIR/FILE_MODE.
package homeperms

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// Secret modes for the config home.
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// SecretPerms returns every config-home secret path with its canonical mode.
func SecretPerms(p paths.Paths) []perms.ManagedPath {
	items := []perms.ManagedPath{
		{Path: p.ConfigDir, Mode: DirMode},
		{Path: p.LogDir(), Mode: DirMode},
		{Path: p.StateDir(), Mode: DirMode},
		{Path: p.SnapshotsDir(), Mode: DirMode},
		{Path: p.DistDir(), Mode: DirMode},
		{Path: p.EnvFile(), Mode: FileMode},
		{Path: p.AgeIdentity(), Mode: FileMode},
		{Path: p.AuditLog(), Mode: FileMode},
		{Path: p.LockFile(), Mode: FileMode},
	}
	for _, pat := range []string{
		filepath.Join(p.DistDir(), "*.age"),
		filepath.Join(p.ConfigDir, "*.age"),
		filepath.Join(p.ConfigDir, "*-identity.txt"),
		filepath.Join(p.SnapshotsDir(), "ssh-*.tar.gz"),
	} {
		matches, _ := filepath.Glob(pat)
		sort.Strings(matches)
		for _, m := range matches {
			items = append(items, perms.ManagedPath{Path: m, Mode: FileMode})
		}
	}
	return items
}
