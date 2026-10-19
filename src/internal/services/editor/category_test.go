package editor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
)

// writeWorkKey puts work's key at rel (under ~/.ssh) and records it at its
// flat path, the state every tree is in before categories.
func writeWorkKey(t *testing.T, p string, rel string, inv string) {
	t.Helper()
	key := filepath.Join(p, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := inventory.New()
	in.Record("SHA256:gh", inventory.KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519", RotateAfterDays: 365,
	})
	if err := in.Save(inv); err != nil {
		t.Fatal(err)
	}
}

func TestSetCategoryMovesTheKeyDirectoryAndRecords(t *testing.T) {
	ed, p := setup(t)
	writeWorkKey(t, p.SSHDir, "profiles/work/work_gh-ed25519", p.Inventory())

	res, err := ed.SetCategory("work", "others")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved || res.From != "profiles/work" || res.To != "profiles/others/work" || res.RecordsUpdated != 1 {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "others", "work", "work_gh-ed25519")); err != nil {
		t.Errorf("key not at its new location: %v", err)
	}
	if got := reload(t, p).Profiles["work"].Category; got != "others" {
		t.Errorf("manifest category = %q", got)
	}
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Keys["SHA256:gh"].Path; got != "~/.ssh/profiles/others/work/work_gh-ed25519" {
		t.Errorf("inventory path = %q", got)
	}
}

// The tree in the field: keys already moved by hand, manifest and inventory
// still flat. Nothing to move; the records catch up.
func TestSetCategoryAfterAHandMoveOnlyUpdatesRecords(t *testing.T) {
	ed, p := setup(t)
	writeWorkKey(t, p.SSHDir, "profiles/others/work/work_gh-ed25519", p.Inventory())

	res, err := ed.SetCategory("work", "others")
	if err != nil {
		t.Fatal(err)
	}
	if res.Moved || res.RecordsUpdated != 1 {
		t.Fatalf("result = %+v, want no move and one record", res)
	}
}

func TestSetCategoryRefusesTwoKeyDirectories(t *testing.T) {
	ed, p := setup(t)
	writeWorkKey(t, p.SSHDir, "profiles/work/work_gh-ed25519", p.Inventory())
	if err := os.MkdirAll(filepath.Join(p.SSHDir, "profiles", "others", "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ed.SetCategory("work", "others"); err == nil {
		t.Fatal("both directories exist; SetCategory must not pick one")
	}
	if got := reload(t, p).Profiles["work"].Category; got != "" {
		t.Errorf("a refused change was saved: category = %q", got)
	}
}

func TestSetCategoryBackToFlat(t *testing.T) {
	ed, p := setup(t)
	writeWorkKey(t, p.SSHDir, "profiles/work/work_gh-ed25519", p.Inventory())
	if _, err := ed.SetCategory("work", "others"); err != nil {
		t.Fatal(err)
	}
	res, err := ed.SetCategory("work", "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved || res.To != "profiles/work" {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")); err != nil {
		t.Errorf("key not back in the flat layout: %v", err)
	}
}
