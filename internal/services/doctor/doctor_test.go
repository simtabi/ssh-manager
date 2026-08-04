package doctor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// "gh" appears in both work and personal -> an alias collision doctor must flag.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [
      {"alias": "gh", "hostname": "github.com", "user": "git"},
      {"alias": "box", "hostname": "10.0.0.2", "user": "deploy"}
    ]},
    "personal": {"key_scope": "per_service", "hosts": [
      {"alias": "gh", "hostname": "github.com", "user": "me"}
    ]}
  }
}`

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestDoctorReportSubchecks(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	cfg := t.TempDir()
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}

	// Build the tree so config is in sync and keys exist.
	if _, err := reconciler.New(p, m, inventory.New(), false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}

	// Clean baseline (modulo the deliberate alias collision in the manifest).
	rep := New(p, m, false).Run(false)
	if !rep.ConfigInSync {
		t.Error("config should be in sync right after reconcile")
	}
	if len(rep.PermIssues) != 0 {
		t.Errorf("expected no perm issues, got %v", rep.PermIssues)
	}
	if len(rep.OrphanKeys) != 0 {
		t.Errorf("expected no orphans, got %v", rep.OrphanKeys)
	}
	if !has(rep.AliasCollisions, "gh (profiles: personal, work)") {
		t.Errorf("alias collision not detected: %v", rep.AliasCollisions)
	}
	if rep.ProvidersSource != "shipped default" {
		t.Errorf("providers source=%q want shipped default", rep.ProvidersSource)
	}

	// Inject defects.
	stray := filepath.Join(ssh, "profiles", "work", "work_stray-ed25519")
	if _, err := keystore.New().Generate(stray, "ed25519", "stray", "", false); err != nil {
		t.Fatal(err)
	}
	oldDir := filepath.Join(ssh, "profiles", "work", "old")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(oldDir, "work_gh-ed25519"), []byte("x"), 0o600) // 1 archived predecessor

	rep = New(p, m, false).Run(false)
	if !has(rep.OrphanKeys, "profiles/work/work_stray-ed25519") {
		t.Errorf("orphan not detected: %v", rep.OrphanKeys)
	}
	if rep.OldKeys["work/work_gh-ed25519"] != 1 {
		t.Errorf("old key count=%v want 1 for work/work_gh-ed25519", rep.OldKeys)
	}

	if runtime.GOOS != "windows" {
		// Loosen perms on a managed key -> a perm issue, and report not OK.
		ghKey := ""
		for _, h := range m.Profiles["work"].Hosts {
			if h.Alias == "box" {
				k, _ := m.ResolvedKeyName("work", h)
				ghKey = filepath.Join(ssh, "profiles", "work", k)
			}
		}
		if err := os.Chmod(ghKey, 0o644); err != nil {
			t.Fatal(err)
		}
		rep = New(p, m, false).Run(false)
		if len(rep.PermIssues) == 0 {
			t.Error("expected a perm issue after loosening a key")
		}
		if rep.OK() {
			t.Error("report should not be OK with perm issues")
		}
	}
}

func TestDoctorJSONShape(t *testing.T) {
	cfg := t.TempDir()
	ssh := t.TempDir()
	rep := New(paths.Paths{SSHDir: ssh, ConfigDir: cfg}, nil, false).Run(false)
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("doctor --json not valid JSON: %v", err)
	}
	// Empty lists/maps must serialize as []/{}, not null (matches as_dict).
	for _, k := range []string{"perm_issues", "orphan_keys", "duplicate_keys", "unpinned_hosts", "alias_collisions"} {
		if _, ok := doc[k].([]any); !ok {
			t.Errorf("%s should be a JSON array, got %T", k, doc[k])
		}
	}
	if _, ok := doc["old_keys"].(map[string]any); !ok {
		t.Errorf("old_keys should be a JSON object, got %T", doc["old_keys"])
	}
	// No manifest -> config considered in sync, nothing to drift from.
	if doc["config_in_sync"] != true {
		t.Errorf("config_in_sync=%v want true", doc["config_in_sync"])
	}
}

// doctor used to print orphans and then report "clean" anyway, so a check whose
// result nothing acted on. A dangling key now decides the verdict.
func mustManifest(t *testing.T, raw string) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestDanglingKeysDecideTheVerdict(t *testing.T) {
	cfg, ssh := t.TempDir(), t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`)

	// A private key with no .pub in a profile nothing declares: the exact case the
	// old orphan check skipped, because it required a .pub to look at.
	dir := filepath.Join(ssh, "profiles", "ghost")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ghost_key-ed25519"), []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep := New(p, m, false).Run(false)
	found := rep.Dangling.ByState(keyaudit.Untracked)
	if len(found) != 1 || found[0].Subject != "profiles/ghost/ghost_key-ed25519" {
		t.Fatalf("untracked findings = %+v", found)
	}
	if rep.OK() {
		t.Error("a tree with an untracked key is not clean")
	}
	text := rep.Format()
	if !strings.Contains(text, "dangling keys:") || !strings.Contains(text, "doctor: issues found") {
		t.Errorf("the report should show the section and the verdict:\n%s", text)
	}
	// orphan_keys keeps its meaning in the JSON, now with the hole closed.
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"orphan_keys"`, `"dangling_keys"`, `profiles/ghost/ghost_key-ed25519`, `"blocking": true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("doctor JSON missing %s:\n%s", want, b)
		}
	}
}

// A key that is merely unminted is the normal state right after `host add`, so
// it warns; --strict is what makes it fail, for CI.
func TestStrictEscalatesWarnings(t *testing.T) {
	cfg, ssh := t.TempDir(), t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}
	m := mustManifest(t, `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`)

	relaxed := New(p, m, false).Run(false)
	if len(relaxed.Dangling.ByState(keyaudit.Missing)) != 1 {
		t.Fatalf("expected the unminted key to be reported: %+v", relaxed.Dangling.Findings)
	}
	if !relaxed.Dangling.OK() {
		t.Error("an unminted key should warn, not fail")
	}
	if New(p, m, false).Run(true).Dangling.OK() {
		t.Error("--strict should fail on it")
	}
}
