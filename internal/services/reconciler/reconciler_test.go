package reconciler

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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

// The same key name in two profiles is the normal case - one person working
// under two orgs uses the same file name in both. Overwrite was keyed by that
// name, so confirming "overwrite imani_github-ed25519" regenerated it in every
// profile that had one: an identity destroyed that the user was never asked
// about, and the deployed public key silently invalidated with it.
const dupNameJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "personal": {"key_scope": "per_service", "hosts": [
      {"alias": "gh-personal", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "adelsaiq": {"key_scope": "per_service", "hosts": [
      {"alias": "gh-adelsaiq", "hostname": "gitlab.com", "user": "git", "key_name": "imani_github-ed25519"}]}
  }
}`

func TestOverwriteIsScopedToOneProfile(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(dupNameJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	inv := inventory.New()
	if _, err := New(p, &m, inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	read := func(profile string) string {
		b, err := os.ReadFile(filepath.Join(ssh, "profiles", profile, "imani_github-ed25519"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	personalBefore, adelsaiqBefore := read("personal"), read("adelsaiq")

	// Both keys are reported for confirmation, each naming its own profile.
	existing, err := New(p, &m, inv, false).ExistingKeys("")
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 2 {
		t.Fatalf("existing = %v, want one per profile", existing)
	}
	profiles := map[string]bool{}
	for _, ref := range existing {
		profiles[ref.Profile] = true
	}
	if !profiles["personal"] || !profiles["adelsaiq"] {
		t.Errorf("both profiles' keys should be offered separately: %v", existing)
	}

	// Say yes to exactly one of them.
	minted, err := New(p, &m, inv, false).Mint("", "",
		map[manifest.KeyRef]bool{{Profile: "personal", KeyName: "imani_github-ed25519"}: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(minted) != 1 || minted[0].Profile != "personal" {
		t.Fatalf("minted = %+v, want only personal's key", minted)
	}
	if read("personal") == personalBefore {
		t.Error("the confirmed key was not regenerated")
	}
	if read("adelsaiq") != adelsaiqBefore {
		t.Fatal("confirming one profile's key destroyed the same-named key in another profile")
	}
	// The untouched profile keeps its archive slot empty: nothing was replaced.
	if _, err := os.Stat(filepath.Join(ssh, "profiles", "adelsaiq", "old")); err == nil {
		t.Error("a key that was never overwritten should have no archived predecessor")
	}
}

// MintRef is the primitive behind `key add`, and its whole contract is the
// refusal: adding a key that already exists must not regenerate it. The private
// key on disk is the half of an identity that remote targets trust through its
// public half, so silently minting a replacement invalidates every deployment
// of that key while reporting success. It returns (nil, nil) instead - nothing
// minted, nothing lost.
func TestMintRefNeverRegeneratesAKeyThatExists(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	inv := inventory.New()
	ref := manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"}

	mk, err := New(p, m, inv, false).MintRef(ref, "")
	if err != nil {
		t.Fatal(err)
	}
	if mk == nil {
		t.Fatal("the first MintRef should mint the key")
	}
	if mk.Profile != "work" || mk.KeyName != ref.KeyName {
		t.Errorf("minted %+v, want %s", mk, ref)
	}
	// Only the named key: MintRef is targeted, not a reconcile.
	if _, err := os.Stat(filepath.Join(ssh, "profiles", "work", "work_box-ed25519")); err == nil {
		t.Error("MintRef minted a key it was not asked for")
	}
	if len(inv.Keys) != 1 {
		t.Errorf("inventory has %d keys, want just the minted one", len(inv.Keys))
	}
	before, err := os.ReadFile(mk.Path)
	if err != nil {
		t.Fatal(err)
	}

	again, err := New(p, m, inv, false).MintRef(ref, "")
	if err != nil {
		t.Fatalf("a second MintRef should be a no-op, not an error: %v", err)
	}
	if again != nil {
		t.Errorf("MintRef reported minting %+v for a key already on disk", again)
	}
	after, err := os.ReadFile(mk.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("MintRef regenerated an existing key; every deployment of it is now dead")
	}
}

// `keygen` is the one command whose purpose is a single key, and it was the only
// selector that would not accept one: `sshmgr keygen work/work_gh-ed25519` was an
// unknown target. Each accepted form is checked by what it selects, since a
// selector that silently matches nothing looks exactly like a successful no-op.
func TestSelectorAcceptsProfileKeyAndHostForms(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	if _, err := New(p, m, inventory.New(), false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	r := New(p, m, inventory.New(), false)

	for _, tc := range []struct {
		selector string
		want     []string // key names, sorted
	}{
		{"", []string{"id_personal", "work_box-ed25519", "work_gh-ed25519"}},
		{"work", []string{"work_box-ed25519", "work_gh-ed25519"}}, // profile
		{"work_gh-ed25519", []string{"work_gh-ed25519"}},          // bare key name
		{"work/work_gh-ed25519", []string{"work_gh-ed25519"}},     // profile/key
		{"gh", []string{"work_gh-ed25519"}},                       // host alias
		{"vps", []string{"id_personal"}},                          // alias -> shared key
		{"personal", []string{"id_personal"}},                     // profile, shared scope
		{"nothing-by-this-name", nil},
	} {
		got, err := r.ExistingKeys(tc.selector)
		if err != nil {
			t.Fatalf("%q: %v", tc.selector, err)
		}
		var names []string
		for _, ref := range got {
			names = append(names, ref.KeyName)
		}
		sort.Strings(names)
		if len(names) != len(tc.want) {
			t.Errorf("%q selected %v, want %v", tc.selector, names, tc.want)
			continue
		}
		for i := range names {
			if names[i] != tc.want[i] {
				t.Errorf("%q selected %v, want %v", tc.selector, names, tc.want)
				break
			}
		}
	}
}

// The inventory is keyed by fingerprint, but a key's identity to the rest of the
// tool is its path. Overwriting a key mints a new fingerprint at the same path,
// so without pruning, the old record stays forever - an orphan the expiry report
// keeps warning about and doctor keeps flagging, for a key that no longer exists.
// The prune is scoped to the path, so a same-named key in another profile - the
// normal case for one person under two orgs - keeps its own record.
func TestOverwritingAKeyLeavesOneInventoryRecordPerPath(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(dupNameJSON), &m); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	inv := inventory.New()
	if _, err := New(p, &m, inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	const personalPath = "~/.ssh/profiles/personal/imani_github-ed25519"
	const adelsaiqPath = "~/.ssh/profiles/adelsaiq/imani_github-ed25519"
	recordFor := func(path string) (string, inventory.KeyRecord) {
		t.Helper()
		var fps []string
		var rec inventory.KeyRecord
		for fp, r := range inv.Keys {
			if r.Path == path {
				fps = append(fps, fp)
				rec = r
			}
		}
		if len(fps) != 1 {
			t.Fatalf("%s has %d inventory records, want exactly 1", path, len(fps))
		}
		return fps[0], rec
	}
	personalBefore, _ := recordFor(personalPath)
	adelsaiqBefore, _ := recordFor(adelsaiqPath)

	if _, err := New(p, &m, inv, false).Mint("", "",
		map[manifest.KeyRef]bool{{Profile: "personal", KeyName: "imani_github-ed25519"}: true}); err != nil {
		t.Fatal(err)
	}

	personalAfter, _ := recordFor(personalPath) // fatals if the old record survived
	if personalAfter == personalBefore {
		t.Error("the overwritten key kept its old fingerprint")
	}
	adelsaiqAfter, _ := recordFor(adelsaiqPath)
	if adelsaiqAfter != adelsaiqBefore {
		t.Error("pruning one profile's record disturbed the same-named key in another")
	}
	if len(inv.Keys) != 2 {
		t.Errorf("inventory holds %d records for 2 keys", len(inv.Keys))
	}
}

// Reconcile used to tighten only ~/.ssh while `doctor --fix` covered both trees,
// so reconciling left the manifest and providers.json at whatever the umask
// produced - and the very next doctor run reported permission problems that
// reconcile had just been asked to prevent.
func TestReconcileTightensTheConfigHomeToo(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	if runtime.GOOS == "windows" {
		t.Skip("permissions are ACLs on Windows; see perms.windowsPermsOK")
	}
	m := loadManifest(t)
	cfg := t.TempDir()
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: cfg}
	// providers.json can hold API tokens; the manifest maps every host and login.
	// Seed both world-readable, as a plain redirect of ssh-manager output would.
	for _, path := range []string{p.Manifest(), p.Providers()} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(p, m, inventory.New(), false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.Manifest(), p.Providers(), p.Inventory()} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
			continue
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s is %04o, want 0600: readable by every local account", filepath.Base(path), mode)
		}
	}
}
