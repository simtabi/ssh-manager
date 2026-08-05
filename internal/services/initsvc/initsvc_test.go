package initsvc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// TestEmbeddedEnvMatchesShipped pins the embedded .env to the template in the
// repo root - the copy a reader finds first, and the one the docs point at. The
// two used to be kept in sync by a script that copied both into the Python
// package; with that gone, this test is what keeps them from drifting.
func TestEmbeddedEnvMatchesShipped(t *testing.T) {
	shipped, err := os.ReadFile("../../../.env-example")
	if err != nil {
		t.Fatalf("the shipped .env-example is missing: %v", err)
	}
	if string(shipped) != string(defaultEnv) {
		t.Error("embedded env_example.txt drifted from data/.env-example")
	}
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestInitSeedsThenIdempotent(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	svc := New(p, true)

	res, err := svc.Run(false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"manifest.json", "inventory.json", ".env"} {
		if !has(res.Created, f) {
			t.Errorf("expected %s created, got %v", f, res.Created)
		}
		if _, err := os.Stat(filepath.Join(p.ConfigDir, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	// providers.json is deliberately NOT seeded.
	if _, err := os.Stat(p.Providers()); err == nil {
		t.Error("providers.json should not be seeded")
	}
	// Dirs scaffolded.
	for _, d := range []string{p.LogDir(), p.SnapshotsDir(), p.DistDir(), p.StateDir()} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("dir %s not created", d)
		}
	}

	// Re-run: everything exists, nothing re-created.
	res2, err := svc.Run(false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Created) != 0 {
		t.Errorf("re-run created %v, want none (idempotent)", res2.Created)
	}
	if !has(res2.Existed, "manifest.json") {
		t.Errorf("re-run should report manifest.json exists: %v", res2.Existed)
	}

	// --force --backup: overwrites + backs up.
	res3, err := svc.Run(true, true, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	if res3.Backup == "" {
		t.Error("force+backup should record a backup dir")
	}
	if _, err := os.Stat(filepath.Join(res3.Backup, "manifest.json")); err != nil {
		t.Errorf("backup of manifest.json not made: %v", err)
	}
}

// `init --force` resets the manifest, which is the user's whole configuration:
// every profile, host, and key declaration. --backup is what makes that
// recoverable, so the backup has to hold the *previous* content, not a copy of
// the freshly written starter.
func TestForceWithBackupPreservesThePreviousManifest(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	svc := New(p, true)
	if _, err := svc.Run(false, false, ""); err != nil {
		t.Fatal(err)
	}
	// Stand in for a manifest the user has actually built up.
	const mine = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	if err := os.WriteFile(p.Manifest(), []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Run(true, true, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup == "" {
		t.Fatal("a --force --backup run should report where the backup went")
	}
	saved, err := os.ReadFile(filepath.Join(res.Backup, "manifest.json"))
	if err != nil {
		t.Fatalf("the previous manifest was not backed up: %v", err)
	}
	if string(saved) != mine {
		t.Errorf("backup holds %q, want the manifest as it was before the reset", saved)
	}
	// The live file really was reset, so the backup is the only copy.
	live, err := os.ReadFile(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if string(live) == mine {
		t.Error("--force did not reset the manifest; the test proves nothing")
	}
	if !has(res.Created, "manifest.json (reset; backup saved)") {
		t.Errorf("Created = %v, want the reset recorded as backed up", res.Created)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(res.Backup, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("the backed-up manifest is %04o, want 0600 - it maps every host and login", mode)
		}
	}
}

// Without --backup the reset is unrecoverable, and the summary has to say so
// rather than leaving the user to infer it from a missing line.
func TestForceWithoutBackupSaysTheResetIsUnrecoverable(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	svc := New(p, true)
	if _, err := svc.Run(false, false, ""); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Run(true, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !has(res.Created, "manifest.json (reset (no backup))") {
		t.Errorf("Created = %v, want the reset marked as unbacked", res.Created)
	}
	if res.Backup != "" {
		t.Errorf("Backup = %q, want empty when none was taken", res.Backup)
	}
}

// The backup is the only thing that makes --force recoverable, so a run that
// cannot write it must not reset anything. Every error out of the copy used to
// be swallowed: the file was reset regardless and the summary said "backup
// saved" over the top of it.
func TestAFailedBackupStopsTheReset(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	svc := New(p, true)
	if _, err := svc.Run(false, false, ""); err != nil {
		t.Fatal(err)
	}
	const mine = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{}}`
	if err := os.WriteFile(p.Manifest(), []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file sitting where the backup directory has to go. Contrived, but
	// it stands in for every way the copy can fail - a full disk, a read-only
	// mount, a permission the user changed - and those are not contrived at all.
	blocker := filepath.Join(p.StateDir(), "init-backup-20260101-000000")
	if err := os.WriteFile(blocker, []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Run(true, true, "20260101-000000"); err == nil {
		t.Fatal("a --force --backup run whose backup fails should error, not reset")
	}
	live, err := os.ReadFile(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if string(live) != mine {
		t.Fatal("the manifest was reset even though its backup could not be written")
	}
}
