package editor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func setup(t *testing.T) (*Editor, paths.Paths) {
	t.Helper()
	cfg := t.TempDir()
	base := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	if err := os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: filepath.Join(t.TempDir(), ".ssh"), ConfigDir: cfg}
	return New(p), p
}

func reload(t *testing.T, p paths.Paths) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func str(s string) *string { return &s }

func TestProfileAndHostCRUD(t *testing.T) {
	ed, p := setup(t)

	// add profile (appended after "work")
	if err := ed.AddProfile("personal", "shared", str("id_personal")); err != nil {
		t.Fatal(err)
	}
	if err := ed.AddProfile("work", "per_service", nil); err == nil {
		t.Error("adding an existing profile should error")
	}
	m := reload(t, p)
	if names := m.ProfileNames(); len(names) != 2 || names[0] != "work" || names[1] != "personal" {
		t.Fatalf("profile order=%v want [work personal]", m.ProfileNames())
	}
	if m.Profiles["personal"].KeyScope != "shared" || *m.Profiles["personal"].KeyName != "id_personal" {
		t.Errorf("personal profile = %+v", m.Profiles["personal"])
	}

	// add host
	if err := ed.AddHost("personal", "vps", HostFields{Hostname: str("1.2.3.4"), User: str("root"), Provider: str("digitalocean"), Tags: []string{"prod"}}); err != nil {
		t.Fatal(err)
	}
	if err := ed.AddHost("personal", "vps", HostFields{Hostname: str("x"), User: str("y")}); err == nil {
		t.Error("duplicate host alias should error")
	}
	m = reload(t, p)
	vps := m.Profiles["personal"].Hosts[0]
	if vps.Alias != "vps" || *vps.Provider != "digitalocean" || vps.Port != 22 || len(vps.Tags) != 1 {
		t.Errorf("added host = %+v", vps)
	}

	// edit host (only provided fields change)
	if err := ed.EditHost("personal", "vps", HostFields{Hostname: str("5.6.7.8"), TokenEnv: str("DO_TOKEN")}); err != nil {
		t.Fatal(err)
	}
	m = reload(t, p)
	vps = m.Profiles["personal"].Hosts[0]
	if vps.Hostname != "5.6.7.8" || *vps.TokenEnv != "DO_TOKEN" || *vps.Provider != "digitalocean" {
		t.Errorf("edited host = %+v (provider should be unchanged)", vps)
	}

	// delete host
	if _, err := ed.DeleteHost("personal", "vps", false); err != nil {
		t.Fatal(err)
	}
	if len(reload(t, p).Profiles["personal"].Hosts) != 0 {
		t.Error("host not deleted")
	}

	// delete profile
	if _, err := ed.DeleteProfile("personal", false); err != nil {
		t.Fatal(err)
	}
	m = reload(t, p)
	if _, ok := m.Profiles["personal"]; ok {
		t.Error("profile not deleted")
	}
	if names := m.ProfileNames(); len(names) != 1 || names[0] != "work" {
		t.Errorf("after delete, profiles=%v want [work]", names)
	}

	// errors on unknown targets
	if _, err := ed.DeleteProfile("nope", false); err == nil {
		t.Error("deleting unknown profile should error")
	}
	if err := ed.EditHost("work", "nope", HostFields{User: str("x")}); err == nil {
		t.Error("editing unknown host should error")
	}
}

func TestSaveValidatesBadEdit(t *testing.T) {
	ed, _ := setup(t)
	// An alias with a slash is rejected by the manifest validators -> not persisted.
	if err := ed.AddHost("work", "bad/alias", HostFields{Hostname: str("h"), User: str("u")}); err == nil {
		t.Error("an invalid alias should fail validation on save")
	}
}
