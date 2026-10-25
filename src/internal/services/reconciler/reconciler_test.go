package reconciler

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
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
	// Windows ACLs on a fresh temp dir may already be tight, so only POSIX
	// modes are guaranteed to need fixing here.
	if runtime.GOOS != "windows" && res.PermsFixed == 0 {
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
	// Two live keys plus the overwritten one, whose record followed it to old/.
	if len(inv.Keys) != 3 {
		t.Errorf("inventory holds %d records for 2 keys and 1 archived predecessor", len(inv.Keys))
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

// Moving a profile into a category by hand, before the manifest says so, leaves
// the key one directory deeper than reconcile looks. Minting there would create
// a second key for the same identity while the deployed one stays live.
func TestReconcileRefusesToMintAKeyThatOnlyMoved(t *testing.T) {
	m := loadManifest(t)
	ssh := t.TempDir()
	moved := filepath.Join(ssh, "profiles", "internal", "personal", "id_personal")
	if err := os.MkdirAll(filepath.Dir(moved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(moved, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}, m, inventory.New(), false)

	_, err := r.Reconcile(true, "")
	if err == nil {
		t.Fatal("reconcile planned a replacement for a key that exists one directory deeper")
	}
	if !strings.Contains(err.Error(), moved) {
		t.Errorf("the error should name where the key is: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ssh, "profiles", "personal", "id_personal")); statErr == nil {
		t.Error("a replacement key was written")
	}
}

// Once the manifest names the category, the same tree is simply in place.
func TestReconcileFindsAKeyInItsCategory(t *testing.T) {
	m := loadManifest(t)
	p := m.Profiles["personal"]
	p.Category = "internal"
	m.Profiles["personal"] = p
	ssh := t.TempDir()
	key := filepath.Join(ssh, "profiles", "internal", "personal", "id_personal")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}, m, inventory.New(), false)
	res, err := r.Reconcile(true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, mk := range res.Minted {
		if strings.Contains(mk.Path, "id_personal") {
			t.Errorf("planned a mint for the categorized key already on disk: %s", mk.Path)
		}
	}
}

// twoProfilesJSON has one key per profile, so a run can mint the first and then
// fail on the second.
const twoProfilesJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "a": {"key_scope": "per_service", "hosts": [{"alias": "a1", "hostname": "a.example", "user": "x"}]},
    "b": {"key_scope": "per_service", "hosts": [{"alias": "b1", "hostname": "b.example", "user": "x"}]}
  }
}`

// recordsAt returns the fingerprints of every inventory record at path.
func recordsAt(inv *inventory.Inventory, path string) []string {
	var fps []string
	for fp, rec := range inv.Keys {
		if rec.Path == path {
			fps = append(fps, fp)
		}
	}
	return fps
}

// A key minted earlier in a run is on disk whether or not a later key fails.
// Returning before the save left it there with no record, and every later run
// saw it as existing and never recorded it either, so expiry tracking was blind
// to it for good.
func TestAFailedMintStillRecordsTheKeysMintedBeforeIt(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	for _, via := range []string{"reconcile", "keygen"} {
		t.Run(via, func(t *testing.T) {
			var m manifest.Manifest
			if err := json.Unmarshal([]byte(twoProfilesJSON), &m); err != nil {
				t.Fatal(err)
			}
			ssh := t.TempDir()
			p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
			aRef := manifest.KeyRef{Profile: "a", KeyName: "a_a1-ed25519"}
			// The keystore refuses to write through a symlink, and a dangling one
			// does not count as the key being present, so b is planned and fails.
			blocked := m.KeyPath(ssh, manifest.KeyRef{Profile: "b", KeyName: "b_b1-ed25519"})
			if err := os.MkdirAll(filepath.Dir(blocked), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/nonexistent", blocked); err != nil {
				t.Fatal(err)
			}

			inv := inventory.New()
			var err error
			if via == "reconcile" {
				_, err = New(p, &m, inv, false).Reconcile(false, "")
			} else {
				_, err = New(p, &m, inv, false).Mint("", "", nil)
			}
			if err == nil {
				t.Fatal("minting through a symlink should fail")
			}
			if _, statErr := os.Stat(m.KeyPath(ssh, aRef)); statErr != nil {
				t.Fatalf("precondition: a's key should have been minted first: %v", statErr)
			}
			saved, loadErr := inventory.Load(p.Inventory())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if got := recordsAt(saved, m.IdentityFile("a", aRef.KeyName)); len(got) != 1 {
				t.Errorf("a's minted key has %d saved records, want 1", len(got))
			}
		})
	}
}

// A declared key on disk with no record - left by an older run that failed, or
// an inventory lost or reset - is recorded by reconcile, with the type and
// rotation interval the manifest gives that key rather than the defaults.
func TestReconcileRecordsAKeyOnDiskThatHasNoRecord(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(declaredKeysJSON), &m); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	first := inventory.New()
	if _, err := New(p, &m, first, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}

	inv := inventory.New() // the keys stay on disk; their records are gone
	res, err := New(p, &m, inv, false).Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Minted) != 0 {
		t.Fatalf("minted %d keys that were already on disk", len(res.Minted))
	}
	if len(inv.Keys) != len(first.Keys) {
		t.Fatalf("inventory has %d records, want %d (one per key on disk)", len(inv.Keys), len(first.Keys))
	}
	for fp, want := range first.Keys {
		got, ok := inv.Keys[fp]
		if !ok {
			t.Errorf("%s (%s) was not recorded", want.Path, fp)
			continue
		}
		if got.Path != want.Path || got.Type != want.Type || got.RotateAfterDays != want.RotateAfterDays {
			t.Errorf("record = %s %s %d, want %s %s %d", got.Path, got.Type, got.RotateAfterDays,
				want.Path, want.Type, want.RotateAfterDays)
		}
		if got.ExpiresOn == nil || *got.ExpiresOn == "" {
			t.Errorf("%s has no expiry, so expiry tracking stays blind to it", got.Path)
		}
	}
	saved, err := inventory.Load(p.Inventory())
	if err != nil || len(saved.Keys) != len(first.Keys) {
		t.Errorf("the recorded keys were not saved: %v", err)
	}
}

// Overwriting a key archives its predecessor to old/, and its record has to go
// with it, as a rotation's does. Deleting it meant a rollback restored a key
// the inventory had no record of: the active key became unrecorded.
func TestOverwriteMovesTheOutgoingRecordToOld(t *testing.T) {
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
	ident := m.IdentityFile("personal", "imani_github-ed25519")
	oldIdent := m.IdentityFile("personal", "old/imani_github-ed25519")
	before := recordsAt(inv, ident)
	if len(before) != 1 {
		t.Fatalf("precondition: %d records at %s", len(before), ident)
	}
	outgoing := before[0]
	rec := inv.Keys[outgoing]
	date := inventory.Today()
	rec.Deployments = []inventory.Deployment{{Target: "gh-personal", Method: "api", Date: &date, Verified: true}}
	inv.Keys[outgoing] = rec

	if _, err := New(p, &m, inv, false).Mint("", "",
		map[manifest.KeyRef]bool{{Profile: "personal", KeyName: "imani_github-ed25519"}: true}); err != nil {
		t.Fatal(err)
	}
	if got := recordsAt(inv, oldIdent); len(got) != 1 || got[0] != outgoing {
		t.Fatalf("records at %s = %v, want the outgoing key %s", oldIdent, got, outgoing)
	}
	if deps := inv.Keys[outgoing].Deployments; len(deps) != 1 {
		t.Errorf("the archived record lost its deployments: %+v", deps)
	}
	if got := recordsAt(inv, ident); len(got) != 1 || got[0] == outgoing {
		t.Errorf("records at %s = %v, want only the new key", ident, got)
	}
}

// A tree that is already correct must report zero fixes: the fixer used to
// count every path it visited, so every reconcile printed "perms fixed on N".
func TestSecondReconcileFixesNoPerms(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	p := paths.Paths{SSHDir: t.TempDir(), ConfigDir: t.TempDir()}
	inv := inventory.New()
	if _, err := New(p, loadManifest(t), inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	res, err := New(p, loadManifest(t), inv, false).Reconcile(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.PermsFixed != 0 {
		t.Errorf("second reconcile fixed %d paths, want 0", res.PermsFixed)
	}
	if !strings.Contains(res.Format(), "perms: ok") {
		t.Errorf("want 'perms: ok' in:\n%s", res.Format())
	}
	// Real drift is still counted, exactly. os.Chmod does not loosen a Windows
	// ACL, so this half is POSIX-only.
	if runtime.GOOS == "windows" {
		return
	}
	cfg := filepath.Join(p.SSHDir, "config")
	if err := os.Chmod(cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ = New(p, loadManifest(t), inv, false).Reconcile(false, "")
	if res.PermsFixed != 1 {
		t.Errorf("one loosened file: fixed %d, want 1", res.PermsFixed)
	}
}
