package snapshots

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, ssh string) {
	t.Helper()
	mk := func(rel, content string) {
		p := filepath.Join(ssh, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk("config", "# root config\n")
	mk("profiles/work/work_gh-ed25519", "PRIVATE\n")
	mk("profiles/work/work_gh-ed25519.pub", "ssh-ed25519 AAAA gh\n")
}

func TestSnapshotRoundTrip(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)

	tarball, err := Snapshot(ssh, snaps, 10, "20260101-000000")
	if err != nil || tarball == "" {
		t.Fatalf("snapshot: %v (%q)", err, tarball)
	}
	if fi, err := os.Stat(tarball); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot should be 0600: %v", err)
	}

	// Mutate the tree, then restore and confirm the original is back.
	os.Remove(filepath.Join(ssh, "profiles/work/work_gh-ed25519"))
	os.WriteFile(filepath.Join(ssh, "config"), []byte("CHANGED\n"), 0o600)
	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(ssh, "config"))
	if string(got) != "# root config\n" {
		t.Errorf("config not restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(ssh, "profiles/work/work_gh-ed25519")); err != nil {
		t.Errorf("private key not restored: %v", err)
	}
}

func TestListAndPrune(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)

	for _, stamp := range []string{"20260101-000001", "20260101-000002", "20260101-000003"} {
		if _, err := Snapshot(ssh, snaps, 10, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if got := List(snaps); len(got) != 3 {
		t.Fatalf("List=%d want 3", len(got))
	}
	// Oldest-first ordering by name (stamps are monotonic here).
	got := List(snaps)
	if filepath.Base(got[0]) != "ssh-20260101-000001.tar.gz" {
		t.Errorf("oldest first wrong: %s", filepath.Base(got[0]))
	}
	if n := Prune(snaps, 2); n != 1 {
		t.Errorf("prune removed %d want 1", n)
	}
	if got := List(snaps); len(got) != 2 {
		t.Errorf("after prune List=%d want 2", len(got))
	}
}

func TestUniqueNameSameStamp(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)
	a, _ := Snapshot(ssh, snaps, 10, "20260101-000000")
	b, _ := Snapshot(ssh, snaps, 10, "20260101-000000")
	if a == b {
		t.Errorf("same-stamp snapshots collided: %s == %s", a, b)
	}
}

func TestCleanTempArtifacts(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	os.WriteFile(filepath.Join(ssh, ".config.123.tmp"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(ssh, "profiles/work/.staging"), 0o700)
	os.WriteFile(filepath.Join(ssh, "profiles/work/.staging/k"), []byte("x"), 0o600)

	removed := CleanTempArtifacts(ssh)
	if len(removed) != 2 {
		t.Errorf("removed=%v want 2 (tmp file + staging dir)", removed)
	}
	if _, err := os.Stat(filepath.Join(ssh, ".config.123.tmp")); err == nil {
		t.Error("temp file not swept")
	}
	if _, err := os.Stat(filepath.Join(ssh, "profiles/work/.staging")); err == nil {
		t.Error(".staging dir not swept")
	}
	// Real files untouched.
	if _, err := os.Stat(filepath.Join(ssh, "config")); err != nil {
		t.Error("real config wrongly removed")
	}
}
