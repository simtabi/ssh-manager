package initsvc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// TestEmbeddedEnvMatchesShipped pins the embedded .env to the shipped template.
func TestEmbeddedEnvMatchesShipped(t *testing.T) {
	shipped, err := os.ReadFile("../../../src/ssh_manager/data/.env-example")
	if err != nil {
		t.Skip("shipped .env-example not present")
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
