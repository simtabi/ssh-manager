// Package fs has atomic-write and directory helpers, ported from the parts of
// src/ssh_manager/util/fs.py the renderer/config writer need. Writes go through a
// temp file + rename so a reader never sees a half-written config, and bytes are
// written as-is (LF stays LF on every platform).
package fs

import (
	"os"
	"path/filepath"
	"strings"
)

// Exists reports whether path exists (following symlinks).
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDir creates path (and parents) and forces mode (MkdirAll is umask-masked,
// so chmod afterwards to guarantee no group/other bits on a secrets dir).
func EnsureDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// WriteTextAtomic writes text to path via a temp file + rename, then chmods it.
func WriteTextAtomic(path, text string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Within reports whether dest lies inside root, for use before writing a path
// that came out of an archive.
//
// This is the check that stops a crafted tar member escaping the directory it is
// being extracted into - `../../.bashrc`, or a name dressed up with a plausible
// prefix. Extraction is rooted somewhere the user can write, so an escape means
// arbitrary file creation from a file they were handed.
//
// It is expressed with filepath.Rel deliberately. String-prefix arithmetic on
// cleaned paths is equivalent when written carefully, but it is harder to read,
// easy to get subtly wrong (a root of /home/user must not admit
// /home/user-evil), and static analysers do not recognise it as a sanitizer -
// so a correct hand-rolled check still shows up as an unfixed path-traversal
// finding. There were two copies of this, one in each form; this is the one.
//
// dest == root is inside: an archive's own root entry is legitimate.
func Within(root, dest string) bool {
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
