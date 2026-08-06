package migratesvc

import (
	"os"
	"path/filepath"
	"runtime"
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
	t.Setenv("USERPROFILE", base) // paths.home() reads this on Windows
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
	_ = os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte("standard"), 0o600)

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

// copyTree is the cross-filesystem fallback: when the legacy home and the new
// one are on different mounts, os.Rename fails with EXDEV and the whole home is
// copied instead. That path never runs in the ordinary case, so it is the one
// most likely to be wrong when it finally does - and by then it is moving the
// user's only copy of their configuration.
func TestCopyTreeCarriesTheWholeHomeAcross(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "moved")
	write := func(rel, body string, mode os.FileMode) string {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return full
	}
	write("manifest.json", `{"version":1}`, 0o600)
	write("log/audit.log", "entry\n", 0o600)
	write("snapshots/ssh-20260101-000000.tar.gz", "archive\n", 0o600)
	write(".state/expiry-cache.json", "{}\n", 0o600)
	// An empty directory still has to arrive: the scaffolding is what init
	// creates, and a missing dist/ means the next bundle write fails.
	if err := os.MkdirAll(filepath.Join(src, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"manifest.json":                        `{"version":1}`,
		"log/audit.log":                        "entry\n",
		"snapshots/ssh-20260101-000000.tar.gz": "archive\n",
		".state/expiry-cache.json":             "{}\n",
	} {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("%s did not survive the copy: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	if fi, err := os.Stat(filepath.Join(dst, "dist")); err != nil || !fi.IsDir() {
		t.Errorf("an empty directory was dropped: %v", err)
	}
}

// Symlinking a config file out to a dotfiles repo or a password store is a
// normal thing to do. filepath.Walk lstats, so a link reaches copyTree as a
// non-directory: opening it would follow it and write the target's bytes into a
// regular file carrying the link's own 0777 mode - leaving the user editing a
// dotfiles copy that nothing reads any more.
func TestCopyTreePreservesSymlinksRatherThanFlatteningThem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	outside := filepath.Join(t.TempDir(), "dotfiles-manifest.json")
	if err := os.WriteFile(outside, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	link := filepath.Join(src, "manifest.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "moved")

	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dst, "manifest.json")
	fi, err := os.Lstat(moved)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was flattened into a %v regular file; edits to the dotfiles copy would stop taking effect",
			fi.Mode().Perm())
	}
	target, err := os.Readlink(moved)
	if err != nil {
		t.Fatal(err)
	}
	if target != outside {
		t.Errorf("link points at %q, want %q", target, outside)
	}
}
