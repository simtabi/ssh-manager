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
	// KnownHostsMode is owner-only, not 0644. ssh has never needed the trust
	// store to be world-readable, and its contents are an inventory of every host
	// the user connects to - which is why the names are hashed as well.
	KnownHostsMode os.FileMode = 0o600
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
	case name == "known_hosts":
		return KnownHostsMode
	case strings.HasSuffix(name, ".pub"):
		return PublicKeyMode // host public keys - not secret
	default:
		return PrivateKeyMode
	}
}

// IterManagedPaths returns (path, canonical mode) for every tool-managed path
// under sshDir: ~/.ssh itself, the root config, the trust store, and the whole
// profiles/ subtree. It deliberately excludes unrelated user files (id_rsa, agent
// sockets), skips symlinks, and skips dot-prefixed cruft it did not create
// (.DS_Store and friends). This is the single enumeration both reconcile (the
// fixer) and doctor (the checker) walk, so they can't disagree.
func IterManagedPaths(sshDir string) []ManagedPath {
	fi, err := os.Lstat(sshDir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	out := []ManagedPath{{sshDir, DirMode}}
	for _, f := range []ManagedPath{
		{filepath.Join(sshDir, "config"), ConfigMode},
		// The top-level trust store is managed now that it is the single store,
		// so its 0600 is actually asserted rather than merely intended.
		{filepath.Join(sshDir, "known_hosts"), KnownHostsMode},
	} {
		if li, err := os.Lstat(f.Path); err == nil && li.Mode()&os.ModeSymlink == 0 {
			out = append(out, f)
		}
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
		if hasForeignDotPart(rel) {
			continue // OS cruft - not ours to chmod
		}
		out = append(out, ManagedPath{p, ModeFor(p, li.IsDir())})
	}
	return out
}

// ourDotDir reports whether a dot-prefixed component is a transient dir this tool
// creates - where rotation and minting stage a key pair before moving it into
// place. Both hold private keys, so a crash leaves real key material behind and
// they have to be locked down like anything else. They were previously lumped in
// with OS cruft and skipped.
func ourDotDir(part string) bool {
	return part == ".staging" || strings.HasPrefix(part, ".mint-")
}

func hasForeignDotPart(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") && !ourDotDir(part) {
			return true
		}
	}
	return false
}
