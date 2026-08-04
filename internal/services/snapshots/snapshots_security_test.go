package snapshots

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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
