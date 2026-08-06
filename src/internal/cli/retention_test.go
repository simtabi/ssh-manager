package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// $SSH_MANAGER_SNAPSHOT_RETAIN was documented but never read.
func TestSnapshotRetainHonoursEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", defaultSnapshotRetain},
		{"3", 3},
		{" 25 ", 25},
		{"1", 1},
		// A bad or zero value falls back rather than silently disabling the
		// rollback safety net for every later command.
		{"0", defaultSnapshotRetain},
		{"-2", defaultSnapshotRetain},
		{"lots", defaultSnapshotRetain},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("SSH_MANAGER_SNAPSHOT_RETAIN", tc.raw)
			if got := snapshotRetain(); got != tc.want {
				t.Errorf("retain %q = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestPruneBundlesKeepsNewestWithSidecars(t *testing.T) {
	dir := t.TempDir()
	var names []string
	for i, stamp := range []string{"20260101", "20260102", "20260103"} {
		age := filepath.Join(dir, "ssh-manager-"+stamp+".age")
		for _, p := range []string{age, age + ".sha256", age + ".contents"} {
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Explicit mtimes: the sort orders by age, and same-second writes
			// would otherwise make the outcome depend on filesystem timestamp
			// resolution.
			when := time.Now().Add(time.Duration(i) * time.Hour)
			if err := os.Chtimes(p, when, when); err != nil {
				t.Fatal(err)
			}
		}
		names = append(names, age)
	}

	removed := pruneBundles(dir, 1)
	if len(removed) != 2 {
		t.Fatalf("expected 2 bundles pruned, got %v", removed)
	}
	if _, err := os.Stat(names[2]); err != nil {
		t.Error("the newest bundle should survive")
	}
	// An orphaned .sha256 would later claim to verify a bundle that is gone.
	for _, gone := range names[:2] {
		for _, p := range []string{gone, gone + ".sha256", gone + ".contents"} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%s should have been pruned", filepath.Base(p))
			}
		}
	}
}

// keep >= the number present must remove nothing, so --keep can be passed
// routinely without eventually eating the last backup.
func TestPruneBundlesKeepsAllWhenUnderLimit(t *testing.T) {
	dir := t.TempDir()
	age := filepath.Join(dir, "ssh-manager-20260101.age")
	if err := os.WriteFile(age, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed := pruneBundles(dir, 5); removed != nil {
		t.Errorf("nothing should be pruned, got %v", removed)
	}
	if _, err := os.Stat(age); err != nil {
		t.Error("the only bundle was deleted")
	}
}
