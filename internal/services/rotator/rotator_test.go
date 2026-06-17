package rotator

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// A web-panel provider (ploi) deploys via the manual path - no network - so the
// staged rotation commits with --allow-unverified, exercising the full
// stage->commit->archive and reverse-move logic deterministically.
const manifestJSON = `{"version":1,"defaults":{"key_type":"ed25519","rotate_after_days":365},
  "profiles":{"vcs":{"key_scope":"per_service","hosts":[
    {"alias":"panel","hostname":"ploi.example","user":"x","provider":"ploi"}]}}}`

func TestRotateThenRollback(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	inv := inventory.New()
	if _, err := reconciler.New(p, &m, inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	keyName, _ := m.ResolvedKeyName("vcs", m.Profiles["vcs"].Hosts[0])
	pdir := filepath.Join(p.SSHDir, "profiles", "vcs")

	// One key recorded after reconcile.
	if len(inv.Keys) != 1 {
		t.Fatalf("after reconcile: %d keys want 1", len(inv.Keys))
	}
	var origFP string
	for fp := range inv.Keys {
		origFP = fp
	}

	// Rotate (allow-unverified, manual provider commits).
	rep, err := New(p, &m, inv).Rotate(keyName, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Committed {
		t.Fatalf("rotate not committed: %+v", rep)
	}
	if rep.OldFingerprint != origFP || rep.NewFingerprint == origFP {
		t.Errorf("fingerprints: old=%s (want %s) new=%s", rep.OldFingerprint, origFP, rep.NewFingerprint)
	}
	if len(rep.Targets) != 1 || !rep.Targets[0].Deployed || rep.Targets[0].Verified {
		t.Errorf("target result = %+v (want deployed, unverified)", rep.Targets)
	}
	// Old archived under /old/, new promoted to canonical, staging gone.
	if !exists(filepath.Join(pdir, "old", keyName)) {
		t.Error("predecessor not archived under old/")
	}
	if exists(filepath.Join(pdir, ".staging")) {
		t.Error(".staging should be removed after commit")
	}
	if len(inv.Keys) != 2 {
		t.Errorf("after rotate: %d keys want 2 (old archived + new)", len(inv.Keys))
	}
	if rec, ok := inv.Keys[origFP]; !ok || rec.Path != "~/.ssh/profiles/vcs/old/"+keyName {
		t.Errorf("old record not archived: %+v", inv.Keys[origFP])
	}
	newFP := rep.NewFingerprint
	if rec, ok := inv.Keys[newFP]; !ok || len(rec.Deployments) != 1 || rec.Deployments[0].Method != "ploi" {
		t.Errorf("new record wrong: %+v", inv.Keys[newFP])
	}

	// Rollback: restore the predecessor.
	rb, err := New(p, &m, inv).Rollback(keyName)
	if err != nil {
		t.Fatal(err)
	}
	if !rb.Committed || rb.NewFingerprint != origFP {
		t.Errorf("rollback should restore %s, got %+v", origFP, rb)
	}
	if _, ok := inv.Keys[newFP]; ok {
		t.Error("rotated-in record should be dropped on rollback")
	}
	if rec, ok := inv.Keys[origFP]; !ok || rec.Path != "~/.ssh/profiles/vcs/"+keyName {
		t.Errorf("restored record should be at the canonical path: %+v", inv.Keys[origFP])
	}
}

func TestRotateMissingKey(t *testing.T) {
	var m manifest.Manifest
	json.Unmarshal([]byte(manifestJSON), &m)
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	if _, err := New(p, &m, inventory.New()).Rotate("vcs_panel-ed25519", true, ""); err == nil {
		t.Error("rotating an absent key should error")
	}
	if _, err := New(p, &m, inventory.New()).Rotate("nope", true, ""); err == nil {
		t.Error("rotating an unknown key should error")
	}
}
