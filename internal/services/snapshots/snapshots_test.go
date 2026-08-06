package snapshots

import (
	"os"
	"path/filepath"
	"runtime"
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
	// File modes are POSIX-only; Windows chmod just toggles the read-only bit.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(tarball); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("snapshot should be 0600: %v", err)
		}
	}

	// Mutate the config, then restore and confirm the original is back.
	_ = os.WriteFile(filepath.Join(ssh, "config"), []byte("CHANGED\n"), 0o600)
	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(ssh, "config"))
	if string(got) != "# root config\n" {
		t.Errorf("config not restored: %q", got)
	}
	// Public keys travel with the snapshot.
	if _, err := os.Stat(filepath.Join(ssh, "profiles/work/work_gh-ed25519.pub")); err != nil {
		t.Errorf("public key not restored: %v", err)
	}
	// The private key was never archived, so restoring must leave the one on disk
	// alone rather than wiping the tree it cannot repopulate.
	if _, err := os.Stat(filepath.Join(ssh, "profiles/work/work_gh-ed25519")); err != nil {
		t.Errorf("restore destroyed a private key it does not hold: %v", err)
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
	_ = os.WriteFile(filepath.Join(ssh, ".config.123.tmp"), []byte("x"), 0o600)
	if err := os.MkdirAll(filepath.Join(ssh, "profiles/work/.staging"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(ssh, "profiles/work/.staging/k"), []byte("x"), 0o600)

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

// Taking the pre-restore snapshot can prune the oldest one - which may be the
// very snapshot being restored from. Reading it back after that point would find
// a file that has just been deleted, so the chosen archive is copied somewhere
// pruning cannot reach before the new snapshot is taken. With retain=1 that
// collision is guaranteed rather than incidental.
func TestRestoreByIDSurvivesPruningTheSnapshotItChose(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)

	// The state we want back, snapshotted.
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte("# the good config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wanted, err := Snapshot(ssh, snaps, 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	// Then the tree is damaged.
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte("# broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// retain=1: the pre-restore snapshot must prune everything older, including
	// the one being restored from.
	chosen, err := RestoreByID(ssh, snaps, 1, "20260101")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if chosen != wanted {
		t.Errorf("chose %s, want %s", filepath.Base(chosen), filepath.Base(wanted))
	}
	got, err := os.ReadFile(filepath.Join(ssh, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# the good config\n" {
		t.Errorf("config = %q, want the snapshotted content", got)
	}
	// The chosen snapshot really was pruned, so the test exercised the collision
	// rather than passing because pruning happened not to reach it.
	if _, err := os.Stat(wanted); err == nil {
		t.Error("retain=1 should have pruned the chosen snapshot; the case was not exercised")
	}
	// And the restore is itself reversible: the damaged tree was snapshotted.
	if len(List(snaps)) == 0 {
		t.Error("no pre-restore snapshot was kept")
	}
}

func TestRestoreByIDReportsWhatItCannotFind(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)

	if _, err := RestoreByID(ssh, snaps, 5, ""); err == nil {
		t.Error("restoring with no snapshots at all should error")
	}
	if _, err := Snapshot(ssh, snaps, 10, "20260101-000000"); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreByID(ssh, snaps, 5, "20991231"); err == nil {
		t.Error("an id matching no snapshot should error, not fall back to the latest")
	}
}
