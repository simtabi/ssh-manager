package knownhosts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

func TestPathFor(t *testing.T) {
	s := New("/h/.ssh")
	if got := s.PathFor(""); got != filepath.Join("/h/.ssh", "known_hosts") {
		t.Errorf("user store path=%q", got)
	}
	if got := s.PathFor("work"); got != filepath.Join("/h/.ssh", "profiles", "work", "known_hosts") {
		t.Errorf("profile store path=%q", got)
	}
}

func TestEnsureAndAddDedup(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)

	created, err := s.Ensure("work")
	if err != nil || !created {
		t.Fatalf("ensure: created=%v err=%v", created, err)
	}
	if c2, _ := s.Ensure("work"); c2 {
		t.Error("second ensure should report not-created")
	}

	n, err := s.Add([]string{"github.com ssh-ed25519 AAAA", "github.com ssh-rsa BBBB"}, "work")
	if err != nil || n != 2 {
		t.Fatalf("add: n=%d err=%v", n, err)
	}
	// Re-adding one existing + one new -> only the new is appended.
	n, _ = s.Add([]string{"github.com ssh-ed25519 AAAA", "gitlab.com ssh-ed25519 CCCC"}, "work")
	if n != 1 {
		t.Errorf("dedup add n=%d want 1", n)
	}
	body, _ := os.ReadFile(s.PathFor("work"))
	if strings.Count(string(body), "github.com ssh-ed25519 AAAA") != 1 {
		t.Errorf("duplicate line written:\n%s", body)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Error("known_hosts should end with a newline")
	}
}

func TestHostInKnownHosts(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte(
		"# comment\n"+
			"github.com,140.82.0.1 ssh-ed25519 AAAA\n"+
			"[example.com]:2222 ssh-rsa BBBB\n"+
			"@cert-authority ca.example.com ssh-ed25519 CCCC\n"), 0o644)

	for _, tok := range []string{"github.com", "140.82.0.1", "[example.com]:2222", "ca.example.com"} {
		if !HostInKnownHosts(kh, tok) {
			t.Errorf("token %q should be found", tok)
		}
	}
	for _, tok := range []string{"gitlab.com", "example.com"} { // example.com only pinned as [host]:port
		if HostInKnownHosts(kh, tok) {
			t.Errorf("token %q should NOT be found", tok)
		}
	}
	if HostInKnownHosts(filepath.Join(dir, "nope"), "github.com") {
		t.Error("missing file should not match")
	}
}

func TestTargetsDedup(t *testing.T) {
	const mj = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[
	    {"alias":"a","hostname":"h.com","user":"u"},
	    {"alias":"b","hostname":"h.com","user":"u"}
	  ]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	// Same (profile, hostname, port) -> deduped to one target.
	targets, err := Targets(&m)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Errorf("targets=%d want 1 (deduped by profile/host/port)", len(targets))
	}
	if ProfileOfAlias(&m, "b") != "work" {
		t.Errorf("ProfileOfAlias(b)=%q want work", ProfileOfAlias(&m, "b"))
	}
}

func TestAutoPinDisabledAndAlreadyTrusted(t *testing.T) {
	const mj = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	s := New(ssh)

	// Disabled via env -> no pins, no network touched.
	off := func(string) string { return "0" }
	if got := s.AutoPin(&m, nil, off); len(got) != 0 {
		t.Errorf("disabled AutoPin added %v want none", got)
	}

	// Enabled but the host is already trusted -> skipped (no network needed).
	os.MkdirAll(filepath.Join(ssh, "profiles", "work"), 0o700)
	os.WriteFile(s.PathFor("work"), []byte("github.com ssh-ed25519 AAAA\n"), 0o644)
	on := func(string) string { return "" }
	if got := s.AutoPin(&m, nil, on); len(got) != 0 {
		t.Errorf("already-trusted host should not be re-pinned, got %v", got)
	}
}
