// Package migratesvc moves a legacy home (~/.config/sshmgr from before the rename,
// or the older ~/.sshmgr) to the OS-standard home, ported from facade.migrate_home.
// It is the guided path for when both already exist (auto-migration can't handle
// that); doctor flags such a stranded legacy home.
package migratesvc

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Result is the outcome of a migrate run.
type Result struct {
	Moved   bool
	Legacy  string
	Home    string
	Backup  string
	Message string
}

// Format renders the message.
func (r Result) Format() string { return r.Message }

// Migrate moves the legacy home into the standard home. If the standard home is
// absent, the legacy is moved in. If both exist, it refuses unless force - with
// force the current home is backed up aside (using stamp) and replaced with the
// legacy one. Mirrors facade.migrate_home (sans the advisory lock).
func Migrate(p paths.Paths, force bool, stamp string) (Result, error) {
	home := p.ConfigDir
	legacy := p.FirstLegacyHome()
	if legacy == "" {
		sibling := filepath.Join(filepath.Dir(home), "sshmgr")
		return Result{Home: home, Legacy: sibling, Message: fmt.Sprintf("no legacy home to migrate (home: %s)", home)}, nil
	}
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		return Result{}, err
	}
	if !exists(home) {
		if err := moveDir(legacy, home); err != nil {
			return Result{}, err
		}
		return Result{Moved: true, Legacy: legacy, Home: home, Message: fmt.Sprintf("migrated %s -> %s", legacy, home)}, nil
	}
	if !force {
		return Result{}, fmt.Errorf("both %s and %s exist. Inspect them, then re-run "+
			"`sshmgr migrate --force` to back up the current home and replace it with the legacy one.", legacy, home)
	}
	backup := filepath.Join(filepath.Dir(home), filepath.Base(home)+".replaced-"+stamp)
	if err := os.Rename(home, backup); err != nil {
		return Result{}, err
	}
	if err := moveDir(legacy, home); err != nil {
		return Result{}, err
	}
	return Result{
		Moved: true, Legacy: legacy, Home: home, Backup: backup,
		Message: fmt.Sprintf("migrated %s -> %s; previous home backed up to %s", legacy, home, backup),
	}, nil
}

// moveDir renames src to dst, falling back to a copy+remove across filesystems
// (the caller guarantees dst is absent). Mirrors facade._move_dir.
func moveDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyTree(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode().Perm())
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }
