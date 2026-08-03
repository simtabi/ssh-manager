package migratesvc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Both move paths preserve the source's modes, so a legacy home created under a
// permissive umask arrived at the new location still group- and world-readable.
// Migrating is the one moment the user would never think to re-check.
func TestMigrateTightensLooseLegacyModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	base := t.TempDir()
	legacy := filepath.Join(base, ".sshmgr")
	home := filepath.Join(base, "std", "ssh-manager")
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: home}

	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	loose := []string{"manifest.json", "inventory.json", "providers.json"}
	for _, n := range loose {
		if err := os.WriteFile(filepath.Join(legacy, n), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// FirstLegacyHome resolves ~/.sshmgr, so point HOME at the fixture.
	t.Setenv("HOME", base)
	res, err := Migrate(p, false, "20260101")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moved {
		t.Fatalf("nothing was migrated: %s", res.Message)
	}

	for _, n := range loose {
		fi, err := os.Stat(filepath.Join(home, n))
		if err != nil {
			t.Fatalf("%s did not survive the migration: %v", n, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %o after migrating, want 0600", n, fi.Mode().Perm())
		}
	}
	fi, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("migrated home is %o, want 0700", fi.Mode().Perm())
	}
}
