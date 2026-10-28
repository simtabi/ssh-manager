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
//
// The same exclusion means a restore can split a keypair: the archive holds a
// .pub whose private half may since have been replaced on disk. A .pub is only
// written beside a private key it is proven to belong to; see foreignPub.
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

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
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
		stagings := manifest.GlobProfileTree(sshDir, ".staging")
		minting := manifest.GlobProfileTree(sshDir, ".mint-*")
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
// exclude private keys, so it would destroy every key in the tree. For the same
// reason a .pub that does not belong to the private key now on disk is left as
// it is (see foreignPub); RestoreByIDIn reports which.
func Restore(tarball, sshDir string) error {
	_, err := restore(tarball, sshDir, "")
	return err
}

// restore is Restore with the dev-mode sandbox admitted when devRoot is set. It
// returns the .pub files it left alone, relative to sshDir and slash-separated.
func restore(tarball, sshDir, devRoot string) ([]string, error) {
	if _, err := os.Stat(tarball); err != nil {
		return nil, fmt.Errorf("snapshot not found: %s", tarball)
	}
	if err := checkTarget(sshDir, devRoot); err != nil {
		return nil, err
	}
	parent := filepath.Dir(sshDir)
	skipped, err := extractTarGz(tarball, parent, foreignPub(parent))
	if err != nil {
		return nil, fmt.Errorf("snapshot is corrupt or not a valid archive: %s: %w", tarball, err)
	}
	prefix := filepath.Base(sshDir) + "/"
	for i, name := range skipped {
		skipped[i] = strings.TrimPrefix(name, prefix)
	}
	return skipped, nil
}

// checkTarget refuses to restore over anything but a .ssh, or the dev sandbox's
// own ssh dir. Extraction is rooted at the target's parent, so aiming it at an
// arbitrary directory would scatter the archive across that directory's siblings.
//
// The sandbox is admitted because the layout says it is one, not because of its
// name: outside dev mode a directory called "ssh" is as arbitrary as any other,
// and in dev mode it must be exactly <devRoot>/ssh, which ResolveDev has already
// checked cannot overlap the real tree.
func checkTarget(sshDir, devRoot string) error {
	sandbox := devRoot != "" &&
		filepath.Clean(sshDir) == filepath.Join(filepath.Clean(devRoot), paths.DevSSHDir)
	if filepath.Base(sshDir) != ".ssh" && !sandbox {
		return fmt.Errorf("refusing to restore over a non-.ssh path: %s", sshDir)
	}
	if fi, err := os.Lstat(sshDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to restore over a symlinked %s (it could point outside the managed tree)", sshDir)
	}
	return nil
}

// foreignPub reports whether an archived .pub would land beside a private key it
// does not belong to, and so must not be written.
//
// Snapshots never hold private keys, so a key regenerated after the snapshot
// would otherwise get its predecessor's public half back. That pair fails
// validate, and deploy would install a key nothing here can use while leaving
// the real one unauthorised. The .pub on disk was written with the key that is
// there now; the snapshot's copy describes a key that is gone.
//
// A .pub restores as before when nothing can contradict it: no private key on
// disk (a 1Password profile keeps only the .pub locally), or the archive carries
// the private key too (a legacy snapshot, whose pair travels together). With a
// private key present, the .pub must derive from it. An encrypted key cannot be
// derived without its passphrase, so its .pub restores only if it is the one
// already on disk: validate reports an absent .pub, but not a wrong one.
func foreignPub(destParent string) func(name string, data []byte, archived map[string]bool) bool {
	ks := keystore.New()
	return func(name string, data []byte, archived map[string]bool) bool {
		privName, ok := strings.CutSuffix(name, ".pub")
		if !ok || archived[privName] {
			return false
		}
		priv := filepath.Join(destParent, filepath.FromSlash(privName))
		if fi, err := os.Stat(priv); err != nil || !fi.Mode().IsRegular() {
			return false
		}
		want := authkeys.KeyBody(string(data))
		if want == "" {
			return true
		}
		if cur, err := os.ReadFile(priv + ".pub"); err == nil && authkeys.KeyBody(string(cur)) == want {
			return false
		}
		got, _, _ := ks.PublicFromPrivate(priv)
		return authkeys.KeyBody(got) != want
	}
}

// extractTarGz lays tarball over destParent. A regular member for which skip
// returns true is not written, and its name is returned. skip is given the set
// of regular members, so it can tell which files the archive carries together.
func extractTarGz(tarball, destParent string, skip func(name string, data []byte, archived map[string]bool) bool) ([]string, error) {
	f, err := os.Open(tarball)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	// Read all members first (fail early if corrupt) before destroying the target.
	type member struct {
		hdr  *tar.Header
		name string // validated, slash-separated, relative
		data []byte
	}
	var members []member
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Validate the name before it is joined to anything. Checking where the
		// path landed afterwards is equivalent when written correctly, but this
		// bounds the untrusted value at its source, which is both easier to read
		// and what a static analyser can follow.
		name := path.Clean(filepath.ToSlash(hdr.Name))
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("refusing path traversal in archive: %s", hdr.Name)
		}
		var data []byte
		if hdr.Typeflag == tar.TypeReg {
			data, err = io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
		}
		members = append(members, member{hdr, name, data})
	}
	archived := map[string]bool{}
	for _, m := range members {
		if m.hdr.Typeflag == tar.TypeReg {
			archived[m.name] = true
		}
	}
	if err := os.MkdirAll(destParent, 0o700); err != nil {
		return nil, err
	}

	// Every write goes through os.Root, which confines it to destParent in the
	// kernel: a name that resolves outside - including through a symlink planted
	// by an earlier member of the same archive - fails in the OS rather than in
	// a check we wrote. The name validation above still runs first, because it
	// gives a better error than a refused syscall, but it is no longer the thing
	// standing between a crafted archive and the filesystem.
	//
	// The string checks it replaces were correct as far as they went. What they
	// could not do is survive being read: they were split across two packages,
	// which is why CodeQL's zipslip rule reported the sink as unsanitized (alert
	// #9) - and an alert nobody can discharge by reading the code is how real
	// ones start getting waved through.
	root, err := os.OpenRoot(destParent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	var skipped []string
	for _, m := range members {
		mode := os.FileMode(m.hdr.Mode).Perm()
		switch m.hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(m.name, mode); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if skip != nil && skip(m.name, m.data, archived) {
				skipped = append(skipped, m.name)
				continue
			}
			if dir := path.Dir(m.name); dir != "." {
				if err := root.MkdirAll(dir, 0o700); err != nil {
					return nil, err
				}
			}
			// Unlink first: the destination may already exist, possibly as a
			// symlink or read-only, and writing through either is wrong.
			if err := root.Remove(m.name); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			if err := root.WriteFile(m.name, m.data, mode); err != nil {
				return nil, err
			}
		}
	}
	return skipped, nil
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
//
// It does not admit the dev sandbox and does not report skipped .pub files; a
// caller holding a resolved layout uses RestoreByIDIn.
func RestoreByID(sshDir, snapshotsDir string, retain int, id string) (string, error) {
	res, err := restoreByID(sshDir, snapshotsDir, "", retain, id)
	if err != nil {
		return "", err
	}
	return res.Snapshot, nil
}

// Result is the outcome of RestoreByIDIn.
type Result struct {
	// Snapshot is the archive restored from.
	Snapshot string
	// Skipped lists the .pub files left as they were because they do not belong
	// to the private key on disk, relative to the ssh dir.
	Skipped []string
}

// RestoreByIDIn is RestoreByID for a resolved layout: it restores p.SSHDir from
// p.SnapshotsDir(), admits the sandbox's ssh dir when p is a dev layout, and
// reports the .pub files it did not overwrite.
func RestoreByIDIn(p paths.Paths, retain int, id string) (Result, error) {
	return restoreByID(p.SSHDir, p.SnapshotsDir(), p.DevRoot, retain, id)
}

func restoreByID(sshDir, snapshotsDir, devRoot string, retain int, id string) (Result, error) {
	// Refuse before the pre-restore snapshot: taking one for a restore that is
	// then refused can prune a snapshot the user still wanted.
	if err := checkTarget(sshDir, devRoot); err != nil {
		return Result{}, err
	}
	chosen, err := choose(snapshotsDir, id)
	if err != nil {
		return Result{}, err
	}
	// Snapshotting the current tree can prune the oldest - possibly `chosen`.
	// Restore from a temp copy that pruning cannot reach.
	tmp, err := os.MkdirTemp("", "sshmgr-restore-")
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	safe := filepath.Join(tmp, filepath.Base(chosen))
	if err := copyFile(chosen, safe); err != nil {
		return Result{}, err
	}
	if _, err := Snapshot(sshDir, snapshotsDir, retain, ""); err != nil {
		return Result{}, err
	}
	skipped, err := restore(safe, sshDir, devRoot)
	if err != nil {
		return Result{}, err
	}
	for _, mp := range perms.IterManagedPaths(sshDir) {
		_ = perms.SetPerms(mp.Path, mp.Mode)
	}
	return Result{Snapshot: chosen, Skipped: skipped}, nil
}

// choose is the snapshot id names in snapshotsDir: the newest whose name
// holds id, or the newest of all when id is "".
func choose(snapshotsDir, id string) (string, error) {
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
	return chosen, nil
}

// Find is the snapshot a restore of id would use, as a path.
func Find(snapshotsDir, id string) (string, error) { return choose(snapshotsDir, id) }

// RestoreInto restores the snapshot id from snapshotsDir over sshDir, as
// RestoreByIDIn does but without its pre-restore snapshot. A preview runs it
// against a copy of ~/.ssh, where there is nothing to snapshot into.
func RestoreInto(sshDir, snapshotsDir, devRoot, id string) (Result, error) {
	if err := checkTarget(sshDir, devRoot); err != nil {
		return Result{}, err
	}
	chosen, err := choose(snapshotsDir, id)
	if err != nil {
		return Result{}, err
	}
	skipped, err := restore(chosen, sshDir, devRoot)
	if err != nil {
		return Result{}, err
	}
	for _, mp := range perms.IterManagedPaths(sshDir) {
		_ = perms.SetPerms(mp.Path, mp.Mode)
	}
	return Result{Snapshot: chosen, Skipped: skipped}, nil
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
