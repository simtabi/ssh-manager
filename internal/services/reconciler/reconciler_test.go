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

// A profile may declare a key no host references, and one whose type and
// rotation differ from the manifest defaults. Both have to survive reconcile:
// the unwired key must be minted (otherwise declaring it does nothing), and the
// overrides must reach ssh-keygen and the inventory record rather than being
// silently replaced by the defaults.
const declaredKeysJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "keys": [{"name": "work_spare-rsa", "type": "rsa", "rotate_after_days": 90}],
      "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git"}]},
    "vault": {"key_scope": "per_service",
      "keys": [{"name": "vault_backup-ed25519"}],
      "hosts": []}
  }
}`

func TestReconcileMintsDeclaredKeysWithTheirOverrides(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(declaredKeysJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	inv := inventory.New()

	res, err := New(p, &m, inv, false).Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	// work's host key + work's declared spare + vault's declared key.
	want := map[string]string{
		"work_gh-ed25519":      filepath.Join(ssh, "profiles", "work", "work_gh-ed25519"),
		"work_spare-rsa":       filepath.Join(ssh, "profiles", "work", "work_spare-rsa"),
		"vault_backup-ed25519": filepath.Join(ssh, "profiles", "vault", "vault_backup-ed25519"),
	}
	if len(res.Minted) != len(want) {
		t.Fatalf("minted %d (%+v), want %d", len(res.Minted), res.Minted, len(want))
	}
	for _, mk := range res.Minted {
		path, ok := want[mk.KeyName]
		if !ok {
			t.Errorf("unexpected minted key %q", mk.KeyName)
			continue
		}
		if mk.Path != path {
			t.Errorf("%s minted at %q, want %q", mk.KeyName, mk.Path, path)
		}
		if _, err := os.Stat(mk.Path); err != nil {
			t.Errorf("private key missing: %s", mk.Path)
		}
	}
	// A profile with keys but no hosts still gets its 0700 directory.
	if fi, err := os.Stat(filepath.Join(ssh, "profiles", "vault")); err != nil || !fi.IsDir() {
		t.Errorf("hostless profile directory not created: %v", err)
	}
	byPath := map[string]inventory.KeyRecord{}
	for _, rec := range inv.Keys {
		byPath[rec.Path] = rec
	}
	spare := byPath["~/.ssh/profiles/work/work_spare-rsa"]
	if spare.Type != "rsa" {
		t.Errorf("declared type not honoured: recorded %q, want rsa", spare.Type)
	}
	if spare.RotateAfterDays != 90 {
		t.Errorf("declared rotate_after_days not honoured: recorded %d, want 90", spare.RotateAfterDays)
	}
	inherited := byPath["~/.ssh/profiles/vault/vault_backup-ed25519"]
	if inherited.Type != "ed25519" || inherited.RotateAfterDays != 365 {
		t.Errorf("undeclared overrides should inherit defaults, got type=%q rotate=%d",
			inherited.Type, inherited.RotateAfterDays)
	}
	// Reconcile stays idempotent with declared keys in play.
	res2, err := New(p, &m, inv, false).Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Minted) != 0 {
		t.Errorf("second reconcile minted %d, want 0", len(res2.Minted))
	}
	if len(res2.ExistingKeys) != len(want) {
		t.Errorf("second reconcile existing=%d, want %d", len(res2.ExistingKeys), len(want))
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
