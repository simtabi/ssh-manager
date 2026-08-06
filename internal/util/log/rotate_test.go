package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// The record is hand-built rather than marshalled from a struct, because field
// order is part of the format. That means the escaping is hand-placed too, and
// the values are not the tool's own strings: hostnames, key names, error text
// and paths all reach it. One unescaped quote makes the line unparseable, and a
// line-per-record log that cannot be parsed is not a trail at all.
func TestAValueThatWouldBreakTheLineIsEscaped(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	nasty := "he said \"hi\"\nevent\": \"forged\\"
	Audit(logPath, "deploy",
		Field{Key: "host", Value: nasty},
		Field{Key: "count", Value: 3},
		Field{Key: "ok", Value: true},
		Field{Key: "detail", Value: nil},
	)

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Still exactly one line, so the value could not inject a second record.
	if n := strings.Count(string(body), "\n"); n != 1 {
		t.Fatalf("a value opened a new record: %d lines in %q", n, body)
	}
	var rec map[string]any
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatalf("the record is not parseable JSON: %v\n%s", err, body)
	}
	if rec["host"] != nasty {
		t.Errorf("host = %q, want the value round-tripped verbatim", rec["host"])
	}
	if rec["event"] != "deploy" {
		t.Errorf("event = %v; a value overwrote a field of the record", rec["event"])
	}
	if rec["count"] != float64(3) || rec["ok"] != true {
		t.Errorf("non-string values did not survive: count=%v ok=%v", rec["count"], rec["ok"])
	}
	if v, ok := rec["detail"]; !ok || v != nil {
		t.Errorf("a nil field should be recorded as null, got %v (present=%v)", v, ok)
	}
}

// Field order is the format: ts and event first, then the caller's fields in the
// order given. Reordering them would not break a JSON parser, but it breaks
// every line-oriented tool a user points at the log - grep, cut, a diff between
// two runs.
func TestTheRecordKeepsTsAndEventFirstThenTheCallersOrder(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	Audit(logPath, "keygen",
		Field{Key: "zebra", Value: "z"},
		Field{Key: "alpha", Value: "a"},
		Field{Key: "middle", Value: "m"},
	)
	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(body))
	var want []string
	for _, k := range []string{`"ts":`, `"event":`, `"zebra":`, `"alpha":`, `"middle":`} {
		i := strings.Index(line, k)
		if i < 0 {
			t.Fatalf("%s missing from %s", k, line)
		}
		want = append(want, k)
		if len(want) > 1 {
			if prev := strings.Index(line, want[len(want)-2]); prev > i {
				t.Errorf("%s appears before %s in %s", k, want[len(want)-2], line)
			}
		}
	}
	// The timestamp is UTC with a Z, not a local offset: two machines' logs have
	// to be comparable, and a local offset makes ordering ambiguous.
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatal(err)
	}
	ts, _ := rec["ts"].(string)
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("ts = %q, want a UTC timestamp", ts)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", ts); err != nil {
		t.Errorf("ts = %q is not the documented format: %v", ts, err)
	}
}

// The log names every host, profile and key the user has touched. It is created
// on demand, deep in a mutating command, so its mode is set where it is opened
// rather than by any init path that may never have run.
func TestAFreshLogAndItsDirectoryAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions are ACLs on Windows")
	}
	base := t.TempDir()
	logPath := filepath.Join(base, "log", "audit.log")
	Audit(logPath, "init")

	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("a fresh audit log is %04o, want 0600", mode)
	}
	di, err := os.Stat(filepath.Dir(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode != 0o700 {
		t.Errorf("the log directory is %04o, want 0700", mode)
	}
}

// I/O failures are swallowed: an audit write must never be the thing that fails
// a rotation or a deploy. Losing a log line is a smaller harm than aborting the
// operation it was describing.
func TestAnUnwritableLogDoesNotFailTheCaller(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent of the log path is a regular file, so nothing can be created.
	Audit(filepath.Join(blocked, "log", "audit.log"), "reconcile",
		Field{Key: "profile", Value: "work"})
}
