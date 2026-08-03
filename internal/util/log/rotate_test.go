package log

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The audit trail names every host, profile and key the user has touched, so an
// unbounded file is a growing privacy artifact as well as a disk-space problem.
func TestAuditRotatesAtCap(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "log", "audit.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", maxAuditBytes)), 0o600); err != nil {
		t.Fatal(err)
	}

	Audit(logPath, "reconcile", Field{Key: "profile", Value: "work"})

	live, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(live), `"event":"reconcile"`) {
		t.Errorf("the new event should be in the fresh log: %q", live)
	}
	if len(live) >= maxAuditBytes {
		t.Error("the live log was not rotated away")
	}
	rotated, err := os.ReadFile(logPath + rotatedSuffix)
	if err != nil {
		t.Fatalf("the previous generation should be kept: %v", err)
	}
	if len(rotated) != maxAuditBytes {
		t.Errorf("rotated log is %d bytes, want %d", len(rotated), maxAuditBytes)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{logPath, logPath + rotatedSuffix} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s is %o, want 0600", filepath.Base(p), fi.Mode().Perm())
			}
		}
	}
}

// Only two generations are kept, so the trail cannot grow without bound.
func TestAuditKeepsOnlyOneRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(logPath+rotatedSuffix, []byte("OLDEST\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", maxAuditBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	Audit(logPath, "rotate")

	rotated, err := os.ReadFile(logPath + rotatedSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rotated), "OLDEST") {
		t.Error("the older generation should have been dropped, not kept")
	}
	if _, err := os.Stat(logPath + rotatedSuffix + rotatedSuffix); err == nil {
		t.Error("rotation should not chain into a third generation")
	}
}

// A log below the cap must be appended to, not rotated on every call.
func TestAuditAppendsBelowCap(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	Audit(logPath, "first")
	Audit(logPath, "second")

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(body), "\n"); n != 2 {
		t.Errorf("expected 2 records, got %d: %q", n, body)
	}
	if _, err := os.Stat(logPath + rotatedSuffix); err == nil {
		t.Error("a small log should not have been rotated")
	}
}
