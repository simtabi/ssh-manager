package rotator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
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
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	if _, err := New(p, &m, inventory.New()).Rotate("vcs_panel-ed25519", true, ""); err == nil {
		t.Error("rotating an absent key should error")
	}
	if _, err := New(p, &m, inventory.New()).Rotate("nope", true, ""); err == nil {
		t.Error("rotating an unknown key should error")
	}
}

// setupRotated builds a reconciled tree and returns the paths a commit touches.
func setupRotated(t *testing.T) (paths.Paths, *manifest.Manifest, *inventory.Inventory, string) {
	t.Helper()
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
	return p, &m, inv, keyName
}

// The property the old four-rename commit violated: at no point may the
// canonical path lack a working private key. A crash there is a lockout the
// user finds the next time they push.
func TestCommitNeverLeavesTheCanonicalPathWithoutAKey(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	pdir := filepath.Join(p.SSHDir, "profiles", "vcs")
	curPriv := filepath.Join(pdir, keyName)
	oldPriv := filepath.Join(pdir, "old", keyName)

	before, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := New(p, m, inv).Rotate(keyName, true, "")
	if err != nil || !rep.Committed {
		t.Fatalf("rotate: %v committed=%v", err, rep.Committed)
	}
	after, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatalf("the canonical private key is gone after a commit: %v", err)
	}
	if string(after) == string(before) {
		t.Error("the canonical key was not replaced")
	}
	archived, err := os.ReadFile(oldPriv)
	if err != nil {
		t.Fatalf("the outgoing key was not archived: %v", err)
	}
	if string(archived) != string(before) {
		t.Error("old/ does not hold the key that was rotated out")
	}
	// The archive is its own file after the swap, not still linked to the live
	// key - otherwise tightening one would tighten the other.
	if err := os.Chmod(oldPriv, 0o400); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(curPriv)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() == 0o400 {
		t.Error("the live key still shares an inode with its archive")
	}
}

// A commit that cannot finish must leave the tree as it found it, not half
// rotated. An unwritable old/ is the cheapest way to make the first step fail.
func TestCommitLeavesTheKeyAloneWhenItCannotArchive(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	pdir := filepath.Join(p.SSHDir, "profiles", "vcs")
	curPriv := filepath.Join(pdir, keyName)
	before, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatal(err)
	}
	// old/ is a regular file, so the archive directory cannot be created.
	if err := os.WriteFile(filepath.Join(pdir, "old"), []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = New(p, m, inv).Rotate(keyName, true, "")
	if err == nil {
		t.Fatal("expected the commit to refuse when it cannot archive")
	}
	if !strings.Contains(err.Error(), "active key is untouched") {
		t.Errorf("the error should say the tree is unharmed: %v", err)
	}
	after, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatalf("the canonical key was lost by a failed commit: %v", err)
	}
	if string(after) != string(before) {
		t.Error("a failed commit changed the active key")
	}
	if _, err := os.Stat(curPriv + ".pub"); err != nil {
		t.Errorf("a failed commit lost the public half: %v", err)
	}
}

// Rollback used to delete the live pair before moving the predecessor in, so a
// failed rename left nothing at all. It must never remove before replacing.
func TestRollbackKeepsAKeyInPlaceThroughout(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	pdir := filepath.Join(p.SSHDir, "profiles", "vcs")
	curPriv := filepath.Join(pdir, keyName)

	original, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(p, m, inv).Rotate(keyName, true, ""); err != nil {
		t.Fatal(err)
	}
	rotatedIn, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := New(p, m, inv).Rollback(keyName)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(curPriv)
	if err != nil {
		t.Fatalf("rollback left the canonical path empty: %v", err)
	}
	if string(restored) != string(original) {
		t.Error("rollback did not restore the original key")
	}
	if string(restored) == string(rotatedIn) {
		t.Error("rollback left the rotated-in key in place")
	}
	// The restored pair matches itself - a stale .pub would make `validate` fail.
	pub, err := os.ReadFile(curPriv + ".pub")
	if err != nil {
		t.Fatalf("rollback left no public key: %v", err)
	}
	derived, _, err := keystore.New().PublicFromPrivate(curPriv)
	if err != nil {
		t.Fatal(err)
	}
	if authkeys.KeyBody(strings.TrimSpace(string(pub))) != authkeys.KeyBody(derived) {
		t.Error("the restored public key does not match the restored private key")
	}
	if !rep.Committed {
		t.Error("a rollback that restored the key should report committed")
	}
}
