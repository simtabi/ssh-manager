// Package snapshots is the local reversible-backup layer for ~/.ssh. A snapshot
// is an owner-only ssh-<stamp>.tar.gz that the mutation guard writes before every
// mutating op, so a change can be rolled back.
//
// Snapshots roll back configuration, not key material. They are plaintext
// archives written on ordinary operations and kept several deep, so including
// private keys would build a rolling unencrypted history of every key the user
// has ever held - a far larger exposure than the mistake being guarded against.
// Restoring therefore overwrites what the archive holds and removes nothing; key
// files are only ever destroyed by an explicit purge, which takes its own
// encrypted backup.
package snapshots

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path" // tar member names are always slash-separated
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/util/perms"
)

const snapshotGlob = "ssh-*.tar.gz"

// tmpArtifact reports whether name is a leftover atomic-write temp file
// (.<name>.*.tmp) - our own prefix, so the sweep never touches unrelated dotfiles.
func tmpArtifact(name string) bool {
	return strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp")
}

// archivable reports whether a file may be written into a plaintext snapshot.
//
// This is an allowlist of things known to be public, not a blocklist of things
// known to be secret: an unrecognised file is assumed to hold key material and
// left out. Getting that backwards would leak a private key the first time
// someone put one somewhere the blocklist did not anticipate.
func archivable(name string) bool {
	return name == "config" ||
		name == "authorized_keys" ||
		strings.HasSuffix(name, ".pub") ||
		strings.HasPrefix(name, "known_hosts")
}

// HoldsKeyMaterial reports whether a snapshot predates the exclusion of private
// keys, so callers can warn that it is a plaintext key archive.
func HoldsKeyMaterial(tarball string) bool {
	f, err := os.Open(tarball)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return false
		}
		if hdr.Typeflag == tar.TypeReg && !archivable(path.Base(hdr.Name)) {
			return true
		}
	}
}

// FindTempArtifacts lists crash residue without removing it: leftover
// .<name>.*.tmp files anywhere under sshDir, plus any stray
// profiles/<p>/.staging or profiles/<p>/.mint-* dir. Paths are absolute and in
// removal order; CleanTempArtifacts is this plus the deletion, so a preview
// (`clean --dry-run`) reports exactly what the sweep would take.
func FindTempArtifacts(sshDir string) []string {
	if _, err := os.Stat(sshDir); err != nil {
		return nil
	}
	var found []string
	_ = filepath.WalkDir(sshDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if tmpArtifact(d.Name()) {
			found = append(found, p)
		}
		return nil
	})
	profiles := filepath.Join(sshDir, "profiles")
	if fi, err := os.Lstat(profiles); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		stagings, _ := filepath.Glob(filepath.Join(profiles, "*", ".staging"))
		minting, _ := filepath.Glob(filepath.Join(profiles, "*", ".mint-*"))
		stagings = append(stagings, minting...)
		sort.Strings(stagings)
		for _, s := range stagings {
			// A symlink here would make RemoveAll follow it out of the tree.
			if fi, err := os.Lstat(s); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
				found = append(found, s)
			}
		}
	}
	return found
}

// CleanTempArtifacts sweeps the crash residue FindTempArtifacts reports. Both
// .staging and .mint-* can hold a private key a crash left behind, so this is a
// leak sweep and not only tidiness. Returns the relative paths removed.
func CleanTempArtifacts(sshDir string) []string {
	var removed []string
	for _, p := range FindTempArtifacts(sshDir) {
		if os.RemoveAll(p) != nil {
			continue
		}
		rel, _ := filepath.Rel(sshDir, p)
		removed = append(removed, filepath.ToSlash(rel))
	}
	return removed
}

// Snapshot tars the archivable part of sshDir into snapshotsDir (owner-only) and
// prunes to the last retain. Private keys are deliberately excluded; see the
// package doc. Returns the snapshot path, or "" if sshDir does not exist. stamp
// "" uses the current time.
func Snapshot(sshDir, snapshotsDir string, retain int, stamp string) (string, error) {
	fi, err := os.Lstat(sshDir)
	if err != nil {
		return "", nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to snapshot a symlinked %s (it could point outside the managed tree)", sshDir)
	}
	if err := os.MkdirAll(snapshotsDir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(snapshotsDir, 0o700)
	if stamp == "" {
		stamp = time.Now().Format("20060102-150405")
	}
	dest := uniquePath(filepath.Join(snapshotsDir, "ssh-"+stamp+".tar.gz"))
	// Owner-only from creation, so there is no window where the archive is
	// group- or world-readable mid-write.
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if err := writeTarGz(f, sshDir); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	_ = os.Chmod(dest, 0o600)
	prune(snapshotsDir, retain)
	return dest, nil
}

// writeTarGz writes a gzip-compressed tar of sshDir, rooted at its base name (so
// it restores back to .../<base>). Directories are recorded so the tree shape
// survives, but only archivable files carry content; anything else is skipped as
// possible key material. Symlinks are skipped rather than recorded, since a
// restored link could point outside the managed tree.
func writeTarGz(w io.Writer, sshDir string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	base := filepath.Base(sshDir)
	root := filepath.Clean(sshDir)
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() && (!fi.Mode().IsRegular() || !archivable(fi.Name())) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name := base
		if rel != "." {
			name = base + "/" + filepath.ToSlash(rel)
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, src)
			_ = src.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	})
	if err != nil {
		_ = tw.Close()
		_ = gz.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

// List returns snapshots oldest->newest (by creation time, then name). Mirrors
// fs.list_snapshots + _snap_sort_key.
func List(snapshotsDir string) []string {
	fi, err := os.Stat(snapshotsDir)
	if err != nil || !fi.IsDir() {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(snapshotsDir, snapshotGlob))
	sort.Slice(matches, func(i, j int) bool {
		mi, mj := mtimeNanos(matches[i]), mtimeNanos(matches[j])
		if mi != mj {
			return mi < mj
		}
		return filepath.Base(matches[i]) < filepath.Base(matches[j])
	})
	return matches
}

// Restore lays a snapshot back over sshDir. The caller snapshots the current tree
// first.
//
// It overwrites the files the archive holds and deletes nothing else. Wiping the
// directory first, as an exact restore would, is no longer possible: snapshots
// exclude private keys, so it would destroy every key in the tree.
func Restore(tarball, sshDir string) error {
	if _, err := os.Stat(tarball); err != nil {
		return fmt.Errorf("snapshot not found: %s", tarball)
	}
	if filepath.Base(sshDir) != ".ssh" {
		return fmt.Errorf("refusing to restore over a non-.ssh path: %s", sshDir)
	}
	if fi, err := os.Lstat(sshDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to restore over a symlinked %s (it could point outside the managed tree)", sshDir)
	}
	parent := filepath.Dir(sshDir)
	if err := extractTarGz(tarball, parent); err != nil {
		return fmt.Errorf("snapshot is corrupt or not a valid archive: %s: %w", tarball, err)
	}
	return nil
}

func extractTarGz(tarball, destParent string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	// Read all members first (fail early if corrupt) before destroying the target.
	type member struct {
		hdr  *tar.Header
		data []byte
	}
	var members []member
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		var data []byte
		if hdr.Typeflag == tar.TypeReg {
			data, err = io.ReadAll(tr)
			if err != nil {
				return err
			}
		}
		members = append(members, member{hdr, data})
	}
	if err := os.MkdirAll(destParent, 0o700); err != nil {
		return err
	}
	cleanParent := filepath.Clean(destParent) + string(os.PathSeparator)
	for _, m := range members {
		dest := filepath.Join(destParent, filepath.FromSlash(m.hdr.Name))
		if !strings.HasPrefix(filepath.Clean(dest)+string(os.PathSeparator), cleanParent) &&
			filepath.Clean(dest) != filepath.Clean(destParent) {
			return fmt.Errorf("refusing path traversal in archive: %s", m.hdr.Name)
		}
		mode := os.FileMode(m.hdr.Mode).Perm()
		switch m.hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, mode); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			// Unlink first: the destination may already exist, possibly as a
			// symlink or read-only, and writing through either is wrong.
			if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.WriteFile(dest, m.data, mode); err != nil {
				return err
			}
		}
	}
	return nil
}

// Prune keeps the keep most-recent snapshots and removes the rest, returning how
// many were removed. keep<=0 removes all. Mirrors facade.prune_snapshots.
func Prune(snapshotsDir string, keep int) int {
	snaps := List(snapshotsDir)
	var remove []string
	if keep > 0 && len(snaps) > keep {
		remove = snaps[:len(snaps)-keep]
	} else if keep <= 0 {
		remove = snaps
	}
	for _, s := range remove {
		_ = os.Remove(s)
	}
	return len(remove)
}

// RestoreByID restores ~/.ssh from a snapshot (latest if id is empty, else the
// last whose name contains id), snapshotting the current tree first so the restore
// is itself reversible, then re-asserting perms. Returns the chosen snapshot path.
// The advisory lock and the pre-restore snapshot are the CLI's mutation guard,
// upstream of this, so they are not duplicated here.
func RestoreByID(sshDir, snapshotsDir string, retain int, id string) (string, error) {
	snaps := List(snapshotsDir)
	if len(snaps) == 0 {
		return "", fmt.Errorf("no snapshots to restore from")
	}
	chosen := snaps[len(snaps)-1]
	if id != "" {
		var match string
		for _, s := range snaps {
			if strings.Contains(filepath.Base(s), id) {
				match = s
			}
		}
		if match == "" {
			return "", fmt.Errorf("no snapshot matching %q", id)
		}
		chosen = match
	}
	// Snapshotting the current tree can prune the oldest - possibly `chosen`.
	// Restore from a temp copy that pruning cannot reach.
	tmp, err := os.MkdirTemp("", "sshmgr-restore-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	safe := filepath.Join(tmp, filepath.Base(chosen))
	if err := copyFile(chosen, safe); err != nil {
		return "", err
	}
	if _, err := Snapshot(sshDir, snapshotsDir, retain, ""); err != nil {
		return "", err
	}
	if err := Restore(safe, sshDir); err != nil {
		return "", err
	}
	for _, mp := range perms.IterManagedPaths(sshDir) {
		_ = perms.SetPerms(mp.Path, mp.Mode)
	}
	return chosen, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); err != nil {
		return path
	}
	base := strings.TrimSuffix(path, ".tar.gz")
	for n := 1; ; n++ {
		cand := fmt.Sprintf("%s-%d.tar.gz", base, n)
		if _, err := os.Stat(cand); err != nil {
			return cand
		}
	}
}

func prune(snapshotsDir string, retain int) {
	snaps := List(snapshotsDir)
	if retain > 0 && len(snaps) > retain {
		for _, s := range snaps[:len(snaps)-retain] {
			_ = os.Remove(s)
		}
	} else if retain <= 0 {
		for _, s := range snaps {
			_ = os.Remove(s)
		}
	}
}

func mtimeNanos(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.ModTime().UnixNano()
}
