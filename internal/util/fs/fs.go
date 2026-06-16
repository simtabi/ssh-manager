// Package fs has atomic-write and directory helpers, ported from the parts of
// src/ssh_manager/util/fs.py the renderer/config writer need. Writes go through a
// temp file + rename so a reader never sees a half-written config, and bytes are
// written as-is (LF stays LF on every platform).
package fs

import (
	"os"
	"path/filepath"
)

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
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
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
