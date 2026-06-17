package migratesvc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// home isolates ~/.sshmgr detection by pointing HOME at a clean temp dir, and
// returns the standard home (ConfigDir) and its legacy "sshmgr" sibling.
func setup(t *testing.T) (paths.Paths, string, string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("HOME", base)
	cfg := filepath.Join(base, "ssh-manager")
	legacy := filepath.Join(base, "sshmgr")
	return paths.Paths{ConfigDir: cfg, SSHDir: filepath.Join(base, ".ssh")}, cfg, legacy
}

func mkLegacy(t *testing.T, legacy, content string) {
	t.Helper()
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "manifest.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateNoLegacy(t *testing.T) {
	p, cfg, _ := setup(t)
	res, err := Migrate(p, false, "TS")
	if err != nil {
		t.Fatal(err)
	}
	if res.Moved || res.Message != "no legacy home to migrate (home: "+cfg+")" {
		t.Errorf("no-legacy result = %+v", res)
	}
}

func TestMigrateMovesIn(t *testing.T) {
	p, cfg, legacy := setup(t)
	mkLegacy(t, legacy, "legacy")
	res, err := Migrate(p, false, "TS")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved || res.Message != "migrated "+legacy+" -> "+cfg {
		t.Errorf("move-in result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(cfg, "manifest.json")); err != nil {
		t.Error("legacy not moved into the standard home")
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Error("legacy dir should be gone after move")
	}
}

func TestMigrateBothExist(t *testing.T) {
	p, cfg, legacy := setup(t)
	mkLegacy(t, legacy, "legacy")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte("standard"), 0o600)

	// No force -> error.
	if _, err := Migrate(p, false, "TS"); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("both-exist without force should error, got %v", err)
	}

	// Force -> backup aside, legacy wins.
	res, err := Migrate(p, true, "TS")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved || res.Backup == "" {
		t.Errorf("force result = %+v", res)
	}
	got, _ := os.ReadFile(filepath.Join(cfg, "manifest.json"))
	if string(got) != "legacy" {
		t.Errorf("after force, standard home should hold legacy data, got %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(res.Backup, "manifest.json")); string(b) != "standard" {
		t.Errorf("backup should hold the previous standard data, got %q", b)
	}
}
