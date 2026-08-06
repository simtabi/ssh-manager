package editor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
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

func TestAddKeyDeclaresAndWires(t *testing.T) {
	ed, p := setup(t)

	// Unwired: declared on the profile, referenced by no host.
	if err := ed.AddKey("work", "work_spare-rsa", str("rsa"), intp(90), ""); err != nil {
		t.Fatal(err)
	}
	m := reload(t, p)
	keys := m.Profiles["work"].Keys
	if len(keys) != 1 || keys[0].Name != "work_spare-rsa" {
		t.Fatalf("declared keys = %+v", keys)
	}
	if keys[0].Type == nil || *keys[0].Type != "rsa" {
		t.Errorf("type override not stored: %+v", keys[0])
	}
	if keys[0].RotateAfterDays == nil || *keys[0].RotateAfterDays != 90 {
		t.Errorf("rotate override not stored: %+v", keys[0])
	}
	if hosts, _ := m.HostsForKey(manifest.KeyRef{Profile: "work", KeyName: "work_spare-rsa"}); len(hosts) != 0 {
		t.Errorf("a key added without --host should be unwired, got hosts %+v", hosts)
	}

	// Wired: the named host now resolves to the new key.
	if err := ed.AddKey("work", "work_gh2-ed25519", nil, nil, "gh"); err != nil {
		t.Fatal(err)
	}
	m = reload(t, p)
	kn, err := m.ResolvedKeyName("work", m.Profiles["work"].Hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	if kn != "work_gh2-ed25519" {
		t.Errorf("host key after wiring = %q, want work_gh2-ed25519", kn)
	}
	if spec, ok := m.KeySpecFor(manifest.KeyRef{Profile: "work", KeyName: "work_gh2-ed25519"}); !ok ||
		spec.Type != nil || spec.RotateAfterDays != nil {
		t.Errorf("unset overrides should stay unset: %+v ok=%v", spec, ok)
	}
}

func TestAddKeyRejections(t *testing.T) {
	ed, p := setup(t)
	if err := ed.AddKey("work", "work_spare-ed25519", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"duplicate declaration": func() error { return ed.AddKey("work", "work_spare-ed25519", nil, nil, "") },
		"unknown profile":       func() error { return ed.AddKey("nope", "k-ed25519", nil, nil, "") },
		"unknown host":          func() error { return ed.AddKey("work", "k-ed25519", nil, nil, "nope") },
		"unsafe name":           func() error { return ed.AddKey("work", "../escape", nil, nil, "") },
		"unknown type":          func() error { return ed.AddKey("work", "k-ed25519", str("quantum"), nil, "") },
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A rejected edit must not have been persisted.
	m := reload(t, p)
	if len(m.Profiles["work"].Keys) != 1 {
		t.Errorf("failed AddKey calls left keys = %+v", m.Profiles["work"].Keys)
	}
}

// In a shared profile every host uses the profile's key_name, so wiring one host
// to a different key would look like it worked and change nothing.
func TestAddKeyRefusesToWireAHostInASharedProfile(t *testing.T) {
	ed, p := setup(t)
	if err := ed.AddProfile("team", "shared", str("team_all-ed25519")); err != nil {
		t.Fatal(err)
	}
	if err := ed.AddHost("team", "box", HostFields{Hostname: str("h"), User: str("u")}); err != nil {
		t.Fatal(err)
	}
	err := ed.AddKey("team", "team_second-ed25519", nil, nil, "box")
	if err == nil {
		t.Fatal("wiring a host in a shared profile should be refused")
	}
	if !strings.Contains(err.Error(), "profile edit") {
		t.Errorf("the refusal should point at the command that does work: %v", err)
	}
	// Declaring without wiring stays legal.
	if err := ed.AddKey("team", "team_second-ed25519", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if m := reload(t, p); len(m.Profiles["team"].Keys) != 1 {
		t.Error("the unwired declaration should have been stored")
	}
}

// EditProfile rebuilds the profile it saves; declared keys must survive that.
func TestEditProfileKeepsDeclaredKeys(t *testing.T) {
	ed, p := setup(t)
	if err := ed.AddKey("work", "work_spare-ed25519", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := ed.EditProfile("work", str("shared"), str("work_shared-ed25519")); err != nil {
		t.Fatal(err)
	}
	m := reload(t, p)
	if len(m.Profiles["work"].Keys) != 1 {
		t.Errorf("editing a profile dropped its declared keys: %+v", m.Profiles["work"])
	}
	if m.Profiles["work"].KeyScope != "shared" {
		t.Error("the edit itself did not apply")
	}
}

func intp(v int) *int { return &v }

// Deleting the last host that used a key does not mean the key is gone: the
// profile may still declare it, in which case the key keeps its files and must
// keep the inventory record that tracks its expiry and deployments. Deriving the
// surviving set from hosts alone dropped that record and left the key untracked.
func TestDeleteHostKeepsTheRecordOfAStillDeclaredKey(t *testing.T) {
	cfg := t.TempDir()
	base := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","keys":[{"name":"work_gh-ed25519"}],
	    "hosts":[
	      {"alias":"gh","hostname":"github.com","user":"git","key_name":"work_gh-ed25519"},
	      {"alias":"box","hostname":"10.0.0.2","user":"deploy","key_name":"work_box-ed25519"}]}}}`
	if err := os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: filepath.Join(t.TempDir(), ".ssh"), ConfigDir: cfg}
	inv := inventory.New()
	for name, fp := range map[string]string{"work_gh-ed25519": "SHA256:gh", "work_box-ed25519": "SHA256:box"} {
		inv.Record(fp, inventory.KeyRecord{
			Profile: "work", Path: "~/.ssh/profiles/work/" + name, Type: "ed25519",
		})
	}
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	ed := New(p)

	// gh's key is declared, so it survives the host that used it.
	res, err := ed.DeleteHost("work", "gh", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PrunedKeys) != 0 {
		t.Errorf("pruned %v, but the key is still declared by the profile", res.PrunedKeys)
	}
	after, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Keys["SHA256:gh"]; !ok {
		t.Error("the record of a still-declared key was pruned")
	}

	// box's key existed only because box named it, so deleting box does take it.
	res, err = ed.DeleteHost("work", "box", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PrunedKeys) != 1 || res.PrunedKeys[0] != "work_box-ed25519" {
		t.Errorf("pruned %v, want the now-unreferenced key", res.PrunedKeys)
	}
	after, err = inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Keys["SHA256:box"]; ok {
		t.Error("a record nothing in the manifest owns should have been pruned")
	}
}

// writeManifest seeds a config home with a manifest and an inventory, and returns
// an Editor over it. The tests below all need a manifest with declared keys and
// records pointing at them, which setup's minimal fixture does not have.
func writeManifest(t *testing.T, manifestJSON string, records map[string]inventory.KeyRecord) (*Editor, paths.Paths) {
	t.Helper()
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "manifest.json"), []byte(manifestJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: filepath.Join(t.TempDir(), ".ssh"), ConfigDir: cfg}
	inv := inventory.New()
	for fp, rec := range records {
		inv.Record(fp, rec)
	}
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	return New(p), p
}

func loadInv(t *testing.T, p paths.Paths) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

const twoHostsOneKeyJSON = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
  "work":{"key_scope":"per_service","keys":[{"name":"shared-ed25519"}],"hosts":[
    {"alias":"gh","hostname":"github.com","user":"git","key_name":"shared-ed25519"},
    {"alias":"box","hostname":"10.0.0.2","user":"deploy","key_name":"shared-ed25519"}]}}}`

// The refusal is the point. A Host block whose IdentityFile no longer exists
// does not fail loudly - ssh reports a bare "Permission denied (publickey)",
// with nothing pointing at the deleted key as the cause. So DeleteKey refuses
// while anything still resolves to it, and names what to fix.
func TestDeleteKeyRefusesWhileHostsStillUseIt(t *testing.T) {
	ed, p := writeManifest(t, twoHostsOneKeyJSON, map[string]inventory.KeyRecord{
		"SHA256:shared": {Profile: "work", Path: "~/.ssh/profiles/work/shared-ed25519", Type: "ed25519"},
	})
	ref := manifest.KeyRef{Profile: "work", KeyName: "shared-ed25519"}

	_, err := ed.DeleteKey(ref, false)
	if err == nil {
		t.Fatal("deleting a key two hosts still use should be refused")
	}
	// Both hosts, so the user can see the whole of what has to be repointed
	// rather than discovering the second one on the next attempt.
	for _, alias := range []string{"gh", "box"} {
		if !strings.Contains(err.Error(), alias) {
			t.Errorf("error should name host %q: %v", alias, err)
		}
	}

	// A refusal must change nothing.
	if keys := reload(t, p).Profiles["work"].Keys; len(keys) != 1 {
		t.Errorf("the declaration was removed despite the refusal: %+v", keys)
	}
	if _, ok := loadInv(t, p).Keys["SHA256:shared"]; !ok {
		t.Error("the inventory record was pruned despite the refusal")
	}
}

func TestDeleteKeyDropsTheDeclarationAndItsRecord(t *testing.T) {
	ed, p := writeManifest(t, twoHostsOneKeyJSON, map[string]inventory.KeyRecord{
		"SHA256:shared": {Profile: "work", Path: "~/.ssh/profiles/work/shared-ed25519", Type: "ed25519"},
	})
	ref := manifest.KeyRef{Profile: "work", KeyName: "shared-ed25519"}

	if _, err := ed.DeleteKey(manifest.KeyRef{Profile: "work", KeyName: "never-declared"}, false); err == nil {
		t.Error("deleting a key the profile does not declare should error")
	}
	if _, err := ed.DeleteKey(manifest.KeyRef{Profile: "nope", KeyName: "x"}, false); err == nil {
		t.Error("deleting from an unknown profile should error")
	}

	// Repoint both hosts, which is what the refusal above told the user to do.
	for _, alias := range []string{"gh", "box"} {
		if err := ed.EditHost("work", alias, HostFields{KeyName: str("other-ed25519")}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ed.DeleteKey(ref, false)
	if err != nil {
		t.Fatalf("an unused key should delete: %v", err)
	}
	if res.Removed != "key work/shared-ed25519" {
		t.Errorf("Removed = %q, want the profile-qualified ref", res.Removed)
	}
	if len(res.PrunedKeys) != 1 || res.PrunedKeys[0] != "shared-ed25519" {
		t.Errorf("PrunedKeys = %v, want the deleted key", res.PrunedKeys)
	}
	if keys := reload(t, p).Profiles["work"].Keys; len(keys) != 0 {
		t.Errorf("declaration survived the delete: %+v", keys)
	}
	if _, ok := loadInv(t, p).Keys["SHA256:shared"]; ok {
		t.Error("the record of a deleted key was left behind")
	}
}

// A profile can declare a key no host ever referenced. Deleting the profile has
// to take that key's record too: the affected set is built from the profile's
// KeyRefs rather than from what its hosts resolve to, so an unwired key does not
// outlive the profile that owned it as a record pointing at nothing.
func TestDeleteProfileTakesTheRecordOfAKeyNoHostUsed(t *testing.T) {
	const j = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]},
	  "vault":{"key_scope":"per_service","keys":[{"name":"vault_backup-ed25519"}],"hosts":[]}}}`
	ed, p := writeManifest(t, j, map[string]inventory.KeyRecord{
		"SHA256:vault": {Profile: "vault", Path: "~/.ssh/profiles/vault/vault_backup-ed25519", Type: "ed25519"},
		"SHA256:gh":    {Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519"},
	})

	res, err := ed.DeleteProfile("vault", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PrunedKeys) != 1 || res.PrunedKeys[0] != "vault_backup-ed25519" {
		t.Errorf("PrunedKeys = %v, want the profile's unwired key", res.PrunedKeys)
	}
	inv := loadInv(t, p)
	if _, ok := inv.Keys["SHA256:vault"]; ok {
		t.Error("a record whose profile no longer exists was left behind")
	}
	if _, ok := inv.Keys["SHA256:gh"]; !ok {
		t.Error("deleting one profile pruned another profile's record")
	}
}

// Two hosts sharing one key each have their own deployment entry on the single
// record. Deleting one host takes its entry and leaves the other: the key is
// still deployed, and reporting it as needs-redeploy would send the user to
// redeploy a key that is already live on the remaining target.
func TestDeletingAHostDropsOnlyItsOwnDeployment(t *testing.T) {
	when := "2026-01-01"
	ed, p := writeManifest(t, twoHostsOneKeyJSON, map[string]inventory.KeyRecord{
		"SHA256:shared": {
			Profile: "work", Path: "~/.ssh/profiles/work/shared-ed25519", Type: "ed25519",
			Deployments: []inventory.Deployment{
				{Target: "gh", Method: "manual", Date: &when, Verified: true},
				{Target: "box", Method: "ssh-copy-id", Date: &when, Verified: true},
			},
		},
	})

	if _, err := ed.DeleteHost("work", "gh", true); err != nil {
		t.Fatal(err)
	}
	rec, ok := loadInv(t, p).Keys["SHA256:shared"]
	if !ok {
		t.Fatal("the key is still declared and still used by box; its record must survive")
	}
	if len(rec.Deployments) != 1 || rec.Deployments[0].Target != "box" {
		t.Fatalf("deployments = %+v, want box's alone", rec.Deployments)
	}
	if !rec.Deployments[0].Verified {
		t.Error("box's deployment was downgraded by another host's deletion")
	}
}
