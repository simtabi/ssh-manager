package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func archive(t *testing.T, ssh, profile, name string, age time.Duration) {
	t.Helper()
	dir := filepath.Join(ssh, "profiles", profile, "old")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, name), filepath.Join(dir, name+".pub")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

// An archived predecessor is an unencrypted private key that nothing references.
// Past the retention window the rotation it belongs to is long confirmed, so
// keeping it is pure exposure - and the user has no reason to go looking.
func TestStaleArchivedKeysAreReported(t *testing.T) {
	ssh := t.TempDir()
	archive(t, ssh, "work", "work_gh-ed25519", 200*24*time.Hour)
	archive(t, ssh, "personal", "imani_gh-ed25519", 3*24*time.Hour)

	counts, stale := archivedKeys(ssh, DefaultOldKeyMaxAge, time.Now())
	if counts["work/work_gh-ed25519"] != 1 || counts["personal/imani_gh-ed25519"] != 1 {
		t.Errorf("archive counts are wrong: %v", counts)
	}
	if len(stale) != 1 {
		t.Fatalf("expected exactly the old one to be stale, got %v", stale)
	}
	if !strings.Contains(stale[0], "work/old/work_gh-ed25519") {
		t.Errorf("wrong key reported stale: %v", stale)
	}
	if !strings.Contains(stale[0], "200 days old") {
		t.Errorf("age should be shown so the user can judge: %v", stale)
	}
	// The .pub half is not key material and must not be double-counted.
	for _, s := range stale {
		if strings.Contains(s, ".pub") {
			t.Errorf("public halves should not be reported: %v", s)
		}
	}
}

// maxAge 0 is the documented escape hatch and must disable the check, not mark
// every archived key stale.
func TestZeroMaxAgeDisablesTheCheck(t *testing.T) {
	ssh := t.TempDir()
	archive(t, ssh, "work", "work_gh-ed25519", 5000*24*time.Hour)

	counts, stale := archivedKeys(ssh, 0, time.Now())
	if len(counts) != 1 {
		t.Errorf("counting should still happen: %v", counts)
	}
	if len(stale) != 0 {
		t.Errorf("the staleness pass should be skipped entirely, got %v", stale)
	}
}

func TestOldKeyMaxAgeHonoursEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"", DefaultOldKeyMaxAge},
		{"30", 30 * 24 * time.Hour},
		{" 7 ", 7 * 24 * time.Hour},
		{"0", 0},
		{"-1", 0},
		{"soon", DefaultOldKeyMaxAge},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			get := func(string) string { return tc.raw }
			if got := OldKeyMaxAge(get); got != tc.want {
				t.Errorf("max age %q = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// Stale archives are a warning, not a failure: they are not blocking anything, and
// failing the verdict would make doctor red until the user deletes old backups.
func TestStaleArchivesDoNotFailTheVerdict(t *testing.T) {
	rep := Report{ConfigInSync: true, StaleOldKeys: []string{"work/old/k (200 days old)"}}
	if !strings.Contains(rep.Format(), "past the retention window") {
		t.Error("stale archives should be surfaced in the report")
	}
	body, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "stale_old_keys") {
		t.Error("stale archives should appear in the JSON view")
	}
}
