package reconciler

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [
      {"alias": "gh", "hostname": "github.com", "user": "git"},
      {"alias": "box", "hostname": "10.0.0.2", "user": "deploy"}
    ]},
    "personal": {"key_scope": "shared", "key_name": "id_personal", "hosts": [
      {"alias": "vps", "hostname": "1.2.3.4", "user": "root"}
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

func TestReconcileMintsRendersAndIsIdempotent(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	cfg := t.TempDir()
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: cfg}
	inv := inventory.New()
	r := New(p, m, inv, false)

	res, err := r.Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	// work has 2 per-service keys; personal shares one -> 3 keys total.
	if len(res.Minted) != 3 {
		t.Fatalf("minted %d want 3", len(res.Minted))
	}
	for _, mk := range res.Minted {
		if _, err := os.Stat(mk.Path); err != nil {
			t.Errorf("private key missing: %s", mk.Path)
		}
		if _, err := os.Stat(mk.Path + ".pub"); err != nil {
			t.Errorf("public key missing: %s.pub", mk.Path)
		}
	}
	// Root config + per-profile configs rendered.
	if _, err := os.Stat(filepath.Join(ssh, "config")); err != nil {
		t.Errorf("root config not written: %v", err)
	}
	if res.Config == nil || len(res.Config.Written) == 0 {
		t.Errorf("expected config writes, got %+v", res.Config)
	}
	if res.PermsFixed == 0 {
		t.Error("expected perms fixed on managed paths")
	}
	// Inventory recorded every minted key, each needs-redeploy with an expiry.
	if len(inv.Keys) != 3 {
		t.Errorf("inventory has %d keys want 3", len(inv.Keys))
	}
	for fp, rec := range inv.Keys {
		if len(rec.Deployments) != 0 {
			t.Errorf("%s should be needs-redeploy (no deployments)", fp)
		}
		if rec.ExpiresOn == nil || *rec.ExpiresOn == "" {
			t.Errorf("%s missing expires_on", fp)
		}
	}
	// inventory.json persisted.
	if _, err := os.Stat(p.Inventory()); err != nil {
		t.Errorf("inventory.json not saved: %v", err)
	}

	// Idempotent + non-destructive: a second run mints nothing.
	res2, err := r.Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Minted) != 0 {
		t.Errorf("second reconcile minted %d, want 0 (idempotent)", len(res2.Minted))
	}
	if len(res2.ExistingKeys) != 3 {
		t.Errorf("second reconcile existing=%d want 3", len(res2.ExistingKeys))
	}
}

func TestReconcileDryRunMintsNothing(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	r := New(p, m, inventory.New(), false)

	res, err := r.Reconcile(true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || len(res.Minted) != 3 {
		t.Errorf("dry-run should plan 3 mints, got %+v", res.Minted)
	}
	for _, mk := range res.Minted {
		if mk.Fingerprint != "(new)" {
			t.Errorf("dry-run mint should be (new), got %q", mk.Fingerprint)
		}
		if _, err := os.Stat(mk.Path); err == nil {
			t.Errorf("dry-run must not write key %s", mk.Path)
		}
	}
	// No keys, no config, no inventory on disk.
	if _, err := os.Stat(filepath.Join(ssh, "config")); err == nil {
		t.Error("dry-run must not write the config")
	}
}
