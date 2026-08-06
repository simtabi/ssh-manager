package snapshots

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// members reads back every regular file in a snapshot as name -> content.
func members(t *testing.T, tarball string) map[string]string {
	t.Helper()
	f, err := os.Open(tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(data)
	}
	return out
}

// A snapshot is written before every mutating command and kept several deep, so
// a private key in one is a rolling plaintext archive of the user's keys.
func TestSnapshotCarriesNoPrivateKey(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	// Key material outside profiles/, and a superseded key in old/, both count.
	if err := os.WriteFile(filepath.Join(ssh, "id_rsa"), []byte("LOOSE PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ssh, "profiles/work/old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "profiles/work/old/work_gh-ed25519"), []byte("ROTATED PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range members(t, tarball) {
		if strings.Contains(content, "PRIVATE") {
			t.Errorf("snapshot member %q carries private key material: %q", name, content)
		}
	}
}

// An unrecognised file could be anything, so it must be treated as secret. If
// this inverts into a blocklist, the next unanticipated key file leaks.
func TestUnknownFilesAreTreatedAsSecret(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	if err := os.WriteFile(filepath.Join(ssh, "something-new"), []byte("SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := members(t, tarball)[".ssh/something-new"]; ok {
		t.Error("an unrecognised file was archived; the allowlist has become a blocklist")
	}
}

// Restore used to RemoveAll the target. With keys excluded from the archive that
// would delete every private key in the tree.
func TestRestoreLeavesUnarchivedFilesAlone(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	// A key minted after the snapshot: rolling back config must not destroy it.
	minted := filepath.Join(ssh, "profiles/work/work_gitlab-ed25519")
	if err := os.WriteFile(minted, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(tarball, ssh); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{minted, filepath.Join(ssh, "profiles/work/work_gh-ed25519")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("restore deleted %s: %v", filepath.Base(p), err)
		}
	}
}

// Restoring over a symlink must replace the link, not write through it to
// whatever it points at.
func TestRestoreReplacesSymlinkedTarget(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("UNTOUCHED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(ssh, "config")
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, cfg); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Restore(tarball, ssh); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "UNTOUCHED\n" {
		t.Errorf("restore wrote through a symlink: %q", got)
	}
	if fi, err := os.Lstat(cfg); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("config should be a regular file after restore: %v", err)
	}
}

func TestHoldsKeyMaterial(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	clean, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	if HoldsKeyMaterial(clean) {
		t.Error("a snapshot written by this version should hold no key material")
	}

	// Stand in for an archive written before keys were excluded.
	legacy := filepath.Join(base, "legacy.tar.gz")
	f, err := os.Create(legacy)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("PRIVATE\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: ".ssh/profiles/work/work_gh-ed25519", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if !HoldsKeyMaterial(legacy) {
		t.Error("a legacy snapshot carrying a private key was not flagged")
	}
}

// craftArchive writes a tar.gz with exactly the members given, bypassing
// Snapshot - which would never produce these.
func craftArchive(t *testing.T, path string, members map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := members[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// Extraction is rooted at the parent of ~/.ssh, so a member naming its way out
// of that directory writes anywhere the user can write - ~/.bashrc, ~/.profile,
// an authorized_keys elsewhere. The guard exists; nothing checked it, and it is
// the one bug in an extractor that turns a file you were handed into code
// execution.
func TestPathTraversalMembersAreRefused(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	outside := filepath.Join(base, "escaped")

	for _, name := range []string{
		"../escaped",         // straight out of the parent
		".ssh/../../escaped", // out via a plausible-looking prefix
		".ssh/../.ssh/../../escaped",
	} {
		tarball := filepath.Join(base, "crafted.tar.gz")
		craftArchive(t, tarball, map[string]string{name: "OWNED\n"})
		if err := Restore(tarball, ssh); err == nil {
			t.Errorf("%q was extracted; it should be refused", name)
		}
		if _, err := os.Stat(outside); err == nil {
			t.Fatalf("%q escaped the destination and wrote %s", name, outside)
		}
	}

	// The ordinary case still works, so the guard is not simply refusing
	// everything - a check that rejects all archives passes the loop above.
	tarball := filepath.Join(base, "ok.tar.gz")
	craftArchive(t, tarball, map[string]string{".ssh/config": "# restored\n"})
	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("an ordinary archive should restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(ssh, "config"))
	if err != nil || string(got) != "# restored\n" {
		t.Errorf("config = %q (%v), want the archived content", got, err)
	}
}

// Restore replaces a whole directory tree, so it checks what it is aimed at
// before it starts. Both refusals matter: the path must be a .ssh, and it must
// not be a symlink - restoring through one would write the archive into whatever
// the link points at, outside the managed tree entirely.
func TestRestoreRefusesATargetItCannotVouchFor(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}

	notSSH := filepath.Join(base, "Documents")
	if err := os.MkdirAll(notSSH, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Restore(tarball, notSSH); err == nil {
		t.Error("restoring over a directory that is not a .ssh should be refused")
	}

	linkBase := t.TempDir()
	real := filepath.Join(linkBase, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkBase, ".ssh")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Restore(tarball, link); err == nil {
		t.Error("restoring over a symlinked .ssh should be refused")
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Error("the refused restore still wrote through the link")
	}

	// A snapshot that is not there at all is an error, not a silent no-op that
	// would read as a successful restore of nothing.
	if err := Restore(filepath.Join(base, "no-such.tar.gz"), ssh); err == nil {
		t.Error("restoring a missing snapshot should error")
	}
}

// A symlink already sitting in the destination is the case string checks cannot
// cover. Every name in the archive below is an ordinary relative path, so the
// name validation passes it and the joined path is textually inside the
// destination - and the write still lands outside, because the OS follows the
// link. os.Root is what refuses it, in the kernel, on the resolved path rather
// than on the spelling of it.
func TestRestoreWillNotWriteThroughASymlinkOutOfTheDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)

	// Somewhere the archive must not be able to reach.
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "authorized_keys")
	const original = "# the real file, must not be rewritten\n"
	if err := os.WriteFile(victim, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// ...and a link into it, planted in the tree being restored over.
	if err := os.Symlink(outside, filepath.Join(ssh, "linked")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	tarball := filepath.Join(base, "crafted.tar.gz")
	craftArchive(t, tarball, map[string]string{".ssh/linked/authorized_keys": "OWNED\n"})

	err := Restore(tarball, ssh)

	got, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("the file outside the destination is gone: %v", readErr)
	}
	if string(got) != original {
		t.Errorf("the archive wrote through a symlink and out of the destination.\n"+
			"%s = %q\nRestore returned: %v", victim, got, err)
	}
}
