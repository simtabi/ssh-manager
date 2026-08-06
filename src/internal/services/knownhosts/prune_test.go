package knownhosts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

func mustMkdir(t *testing.T, base string, parts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(append([]string{base}, parts...)...), 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, base, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(rel)), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func osStat(base, rel string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(base, filepath.FromSlash(rel)))
}

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

// The one-shot migration off per-profile stores has to merge what is there
// (plaintext, pre-hashing) into the single file and remove the legacy files -
// otherwise every rendered UserKnownHostsFile ~/.ssh/known_hosts line points at
// a store missing the entries the old per-profile files held.
func TestMigrateLegacyStoresMergesAndRemoves(t *testing.T) {
	ssh := t.TempDir()
	mustMkdir(t, ssh, "profiles", "work")
	mustMkdir(t, ssh, "profiles", "personal")
	mustWrite(t, ssh, "profiles/work/known_hosts", "github.com ssh-ed25519 AAAA\n")
	mustWrite(t, ssh, "profiles/personal/known_hosts", "gitlab.com ssh-ed25519 BBBB\n")

	s := New(ssh)
	rep, err := s.MigrateLegacyStores()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Merged != 2 {
		t.Errorf("merged=%d want 2", rep.Merged)
	}
	if len(rep.Removed) != 2 {
		t.Errorf("removed=%v want 2 files", rep.Removed)
	}
	for _, legacy := range []string{"profiles/work/known_hosts", "profiles/personal/known_hosts"} {
		if _, err := osStat(ssh, legacy); err == nil {
			t.Errorf("%s should have been deleted", legacy)
		}
	}
	for _, host := range []string{"github.com", "gitlab.com"} {
		if !HostInKnownHosts(s.Path(), host) {
			t.Errorf("%s should have been merged into the single store", host)
		}
	}

	// A tree with no legacy stores left is a no-op.
	rep2, err := s.MigrateLegacyStores()
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Merged != 0 || len(rep2.Removed) != 0 {
		t.Errorf("second migration should be a no-op, got %+v", rep2)
	}
}

// A --dry-run is only trustworthy if it is computed by the same code that does
// the work. These assert the previews and the mutations agree on both counts
// and contents.
func TestCandidatesMatchWhatPruneAndAdoptDo(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	// Tagged and live, tagged and stale, untagged and live, untagged and stale.
	if _, err := s.Add([]string{"github.com ssh-ed25519 AAAAlive", "gone.example.com ssh-ed25519 AAAAstale"}); err != nil {
		t.Fatal(err)
	}
	existing, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	mine := "github.com ssh-rsa AAAAmine\nsomewhere.else ssh-rsa AAAAtheirs\n"
	if err := os.WriteFile(s.Path(), append(existing, []byte(mine)...), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mustManifest(t, oneHostJSON)

	adoptable, err := s.AdoptCandidates(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(adoptable) != 1 || adoptable[0].Token != "github.com" || adoptable[0].Keytype != "ssh-rsa" {
		t.Fatalf("adopt candidates = %+v, want only the untagged github.com line", adoptable)
	}
	prunable, err := s.PruneCandidates(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(prunable) != 1 {
		t.Fatalf("prune candidates = %+v, want only the tagged stale line", prunable)
	}
	// Hashed and matching no live host, so it cannot be named - only identified.
	if prunable[0].Token != "" || prunable[0].Name() != "(hashed host)" {
		t.Errorf("a stale hashed line should not claim a host name: %+v", prunable[0])
	}

	adopted, err := s.Adopt(m)
	if err != nil {
		t.Fatal(err)
	}
	if adopted != len(adoptable) {
		t.Errorf("adopted %d but predicted %d", adopted, len(adoptable))
	}
	pruned, err := s.Prune(m)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != len(prunable) {
		t.Errorf("pruned %d but predicted %d", pruned, len(prunable))
	}
	// The user's unrelated pin is still untouched by both operations.
	body, _ := os.ReadFile(s.Path())
	if !strings.Contains(string(body), "somewhere.else") {
		t.Errorf("a foreign pin was removed:\n%s", body)
	}
}

// Adopting makes a line prunable later, never in the same run - it matches a
// live host by definition, which is why it was adoptable at all.
func TestAdoptDoesNotMakeALinePrunableNow(t *testing.T) {
	ssh := t.TempDir()
	s := New(ssh)
	if err := os.WriteFile(s.Path(), []byte("github.com ssh-ed25519 AAAAmine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mustManifest(t, oneHostJSON)
	if _, err := s.Adopt(m); err != nil {
		t.Fatal(err)
	}
	pruned, err := s.Prune(m)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 0 {
		t.Errorf("pruned %d adopted-but-live line(s), want 0", pruned)
	}
	// Once the host is gone, the adopted line is sshmgr's to remove.
	pruned, err = s.Prune(mustManifest(t, emptyManifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Errorf("pruned %d, want the adopted line once its host went away", pruned)
	}
}
