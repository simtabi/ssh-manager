// Package perms centralizes the file modes ssh-manager enforces and applies them
// in a platform-correct way - POSIX chmod on Unix, ACLs via icacls on Windows.
// Ported from util/perms.py + the platforms/*.set_perms layer.
package perms

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Modes SSH expects. Private keys and configs must not be group/other readable;
// dirs are 0700; host public keys are world-readable.
const (
	DirMode        os.FileMode = 0o700
	PrivateKeyMode os.FileMode = 0o600
	ConfigMode     os.FileMode = 0o600
	PublicKeyMode  os.FileMode = 0o644
)

// ManagedPath is a tool-managed path and the canonical mode it should carry.
type ManagedPath struct {
	Path string
	Mode os.FileMode
}

// ModeFor returns the canonical mode for a path by its role. Mirrors perms.mode_for.
func ModeFor(path string, isDir bool) os.FileMode {
	if isDir {
		return DirMode
	}
	name := filepath.Base(path)
	switch {
	case name == "config":
		return ConfigMode
	case strings.HasSuffix(name, ".pub") || name == "known_hosts":
		return PublicKeyMode // host public keys - not secret
	default:
		return PrivateKeyMode
	}
}

// IterManagedPaths returns (path, canonical mode) for every tool-managed path
// under sshDir: ~/.ssh itself, the root config, and the whole profiles/ subtree.
// It deliberately excludes unrelated user files (id_rsa, top-level known_hosts,
// agent sockets), skips symlinks, and skips dot-prefixed cruft (.DS_Store,
// .staging). Mirrors perms.iter_managed_paths; this is the single enumeration both
// reconcile (the fixer) and doctor (the checker) walk, so they can't disagree.
func IterManagedPaths(sshDir string) []ManagedPath {
	fi, err := os.Lstat(sshDir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	out := []ManagedPath{{sshDir, DirMode}}
	rootConfig := filepath.Join(sshDir, "config")
	if li, err := os.Lstat(rootConfig); err == nil && li.Mode()&os.ModeSymlink == 0 {
		out = append(out, ManagedPath{rootConfig, ConfigMode})
	}
	profiles := filepath.Join(sshDir, "profiles")
	pfi, err := os.Lstat(profiles)
	if err != nil || pfi.Mode()&os.ModeSymlink != 0 || !pfi.IsDir() {
		return out
	}
	out = append(out, ManagedPath{profiles, DirMode})

	var paths []string
	_ = filepath.WalkDir(profiles, func(p string, _ fs.DirEntry, err error) error {
		if err == nil && p != profiles {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	for _, p := range paths {
		li, err := os.Lstat(p)
		if err != nil || li.Mode()&os.ModeSymlink != 0 {
			continue
		}
		rel, _ := filepath.Rel(profiles, p)
		if hasDotPart(rel) {
			continue // OS cruft / transient dirs - not ours to chmod
		}
		out = append(out, ManagedPath{p, ModeFor(p, li.IsDir())})
	}
	return out
}

func hasDotPart(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}
