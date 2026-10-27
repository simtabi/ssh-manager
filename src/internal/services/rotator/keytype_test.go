package rotator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// A key declared with its own type keeps it across a rotation. Rotation used
// defaults.key_type, so an ecdsa key came back as ed25519 under its ecdsa name,
// and its inventory record said ed25519 too.
func TestRotateKeepsTheDeclaredKeyType(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	const js = `{"version":1,"defaults":{"key_type":"ed25519","rotate_after_days":365},
	  "profiles":{"vcs":{"key_scope":"per_service","key_comment":"{profile}-{alias}-{date}",
	    "keys":[{"name":"vcs_panel-ecdsa","type":"ecdsa"}],
	    "hosts":[{"alias":"panel","hostname":"ploi.example","user":"x","provider":"ploi","key_name":"vcs_panel-ecdsa"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	inv := inventory.New()
	if _, err := reconciler.New(p, &m, inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	rep, err := New(p, &m, inv).Rotate("vcs_panel-ecdsa", true, "")
	if err != nil || !rep.Committed {
		t.Fatalf("rotate: %v %+v", err, rep)
	}
	pub, err := os.ReadFile(filepath.Join(p.SSHDir, "profiles", "vcs", "vcs_panel-ecdsa.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pub), "ecdsa-sha2-") {
		t.Errorf("the rotated key should still be ecdsa: %.40s", pub)
	}
	rec := inv.Keys[rep.NewFingerprint]
	if rec.Type != "ecdsa" {
		t.Errorf("the new record should say ecdsa, got %q", rec.Type)
	}
	want := "vcs-panel-" + inventory.Today()
	if rec.Comment == nil || *rec.Comment != want || !strings.Contains(string(pub), " "+want) {
		t.Errorf("record and key should both carry %q: record %v, key %q", want, rec.Comment, pub)
	}
}
