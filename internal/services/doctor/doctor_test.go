package doctor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
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
	rep := New(p, m, false).Run()
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
	os.MkdirAll(oldDir, 0o700)
	os.WriteFile(filepath.Join(oldDir, "work_gh-ed25519"), []byte("x"), 0o600) // 1 archived predecessor

	rep = New(p, m, false).Run()
	if !has(rep.OrphanKeys, "profiles/work/work_stray-ed25519") {
		t.Errorf("orphan not detected: %v", rep.OrphanKeys)
	}
	if rep.OldKeys["work_gh-ed25519"] != 1 {
		t.Errorf("old key count=%v want 1", rep.OldKeys["work_gh-ed25519"])
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
		os.Chmod(ghKey, 0o644)
		rep = New(p, m, false).Run()
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
	rep := New(paths.Paths{SSHDir: ssh, ConfigDir: cfg}, nil, false).Run()
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
