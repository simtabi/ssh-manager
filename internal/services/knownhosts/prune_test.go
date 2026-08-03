package knownhosts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

func mustManifest(t *testing.T, raw string) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

const oneHostJSON = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`

const emptyManifestJSON = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{}}`

// A tagged pin belonging to no remaining manifest host - the profile that
// declared it was deleted - is exactly what prune exists to clean up.
func TestPruneRemovesTaggedLinesWithNoLiveHost(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	if _, err := s.Add([]string{"github.com ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}
	// Simulate the profile that owned github.com having been deleted: prune
	// against a manifest with no hosts at all.
	n, err := s.Prune(mustManifest(t, emptyManifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed=%d want 1", n)
	}
	body, _ := os.ReadFile(s.Path())
	if strings.TrimSpace(string(body)) != "" {
		t.Errorf("expected an empty store after pruning the only entry:\n%s", body)
	}
}

// Deleting one profile can never strand or unpin a host another profile still
// resolves to - reference counting, not ownership.
func TestPruneKeepsLineIfAnyHostStillResolvesIt(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	if _, err := s.Add([]string{"github.com ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}
	// A manifest where some other profile still has a host at github.com.
	n, err := s.Prune(mustManifest(t, oneHostJSON))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("removed=%d want 0 (github.com is still live)", n)
	}
	if !HostInKnownHosts(s.Path(), "github.com") {
		t.Error("github.com should still be pinned")
	}
}

// Untagged lines are not sshmgr's to manage - the user's own pins, or anything
// else already in the file - so prune must never remove them, live host or not.
func TestPruneNeverTouchesUntaggedLines(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	if err := os.WriteFile(s.Path(), []byte("gitlab.com ssh-ed25519 ZZZZ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(mustManifest(t, emptyManifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("removed=%d want 0 (untagged lines are not sshmgr's to prune)", n)
	}
	if !HostInKnownHosts(s.Path(), "gitlab.com") {
		t.Error("the untagged pin must survive prune")
	}
}

// Adopt is opt-in: an untagged pin matching a live manifest host becomes
// eligible for future pruning only once explicitly adopted.
func TestAdoptTagsOnlyMatchingUntaggedLines(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	if err := os.WriteFile(s.Path(),
		[]byte("github.com ssh-ed25519 AAAA\ngitlab.com ssh-ed25519 ZZZZ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.Adopt(mustManifest(t, oneHostJSON)) // manifest only knows github.com
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("adopted=%d want 1", n)
	}
	body, _ := os.ReadFile(s.Path())
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		parsed, ok := parseKHLine(line)
		if !ok {
			t.Fatalf("unparseable line: %q", line)
		}
		wantTagged := strings.Contains(line, "AAAA")
		if parsed.tagged() != wantTagged {
			t.Errorf("line %q tagged=%v want %v", line, parsed.tagged(), wantTagged)
		}
	}
	// Adopting twice must not double-tag or duplicate.
	if n2, _ := s.Adopt(mustManifest(t, oneHostJSON)); n2 != 0 {
		t.Errorf("re-adopt should be a no-op, adopted %d more", n2)
	}
}
