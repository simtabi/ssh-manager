package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// work owns a wired key and a declared-but-unwired spare; personal owns a key
// pinned to the same hostname, which is what proves pruning is reference
// counted rather than ownership based.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "keys": [{"name": "work_spare-ed25519"}],
      "hosts": [{"alias": "gh-work", "hostname": "github.com", "user": "git", "key_name": "work_gh-ed25519"}]},
    "personal": {"key_scope": "per_service",
      "hosts": [{"alias": "gh-personal", "hostname": "github.com", "user": "git", "key_name": "personal_gh-ed25519"}]}
  }
}`

const inventoryJSON = `{
  "version": 1,
  "keys": {
    "SHA256:work": {"profile": "work", "path": "~/.ssh/profiles/work/work_gh-ed25519",
      "type": "ed25519", "comment": null, "created": "2026-01-01", "rotate_after_days": 365,
      "expires_on": "2027-01-01", "deployments": [{"target": "gh-work", "method": "manual", "date": null, "verified": true}]},
    "SHA256:spare": {"profile": "work", "path": "~/.ssh/profiles/work/work_spare-ed25519",
      "type": "ed25519", "comment": null, "created": "2026-01-01", "rotate_after_days": 365,
      "expires_on": "2027-01-01", "deployments": []}
  }
}`

func fixture(t *testing.T) paths.Paths {
	t.Helper()
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	if err := os.MkdirAll(p.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, p.Manifest(), manifestJSON, 0o600)
	write(t, p.Inventory(), inventoryJSON, 0o600)

	for _, k := range []struct{ profile, name string }{
		{"work", "work_gh-ed25519"}, {"work", "work_spare-ed25519"}, {"personal", "personal_gh-ed25519"},
	} {
		dir := filepath.Join(p.SSHDir, "profiles", k.profile)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, k.name), "PRIVATE\n", 0o600)
		write(t, filepath.Join(dir, k.name+".pub"), "ssh-ed25519 AAAA "+k.name+"\n", 0o644)
	}
	// A rotation predecessor parked in old/, which a purge has to take with it.
	oldDir := filepath.Join(p.SSHDir, "profiles", "work", "old")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(oldDir, "work_gh-ed25519"), "OLD PRIVATE\n", 0o600)

	// One pin for github.com, tagged as sshmgr-owned, shared by both profiles.
	if _, err := knownhosts.New(p.SSHDir).Add([]string{"github.com ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}
	return p
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func onDisk(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func loadManifest(t *testing.T, p paths.Paths) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Without --purge the profile disappears from every piece of state sshmgr owns,
// the config is re-rendered on the spot rather than left stale until the next
// reconcile, and the key files survive so the delete stays recoverable.
func TestDeleteProfileCleansStateButKeepsKeys(t *testing.T) {
	p := fixture(t)
	res, err := New(p, false).DeleteProfile("work", Options{})
	if err != nil {
		t.Fatal(err)
	}

	m := loadManifest(t, p)
	if _, ok := m.Profiles["work"]; ok {
		t.Error("profile still in the manifest")
	}
	cfg, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatalf("config not re-rendered: %v", err)
	}
	if strings.Contains(string(cfg), "gh-work") {
		t.Errorf("deleted profile's Host block still rendered:\n%s", cfg)
	}
	if !strings.Contains(string(cfg), "gh-personal") {
		t.Errorf("surviving profile's Host block was dropped:\n%s", cfg)
	}
	if len(res.ConfigWritten) == 0 {
		t.Error("the result should report the re-render")
	}
	if len(res.PrunedRecords) != 2 {
		t.Errorf("pruned inventory records = %v, want both of work's keys", res.PrunedRecords)
	}
	// personal still resolves github.com, so the shared pin must survive.
	if res.PrunedPins != 0 {
		t.Errorf("pruned %d pins, want 0 - another profile still resolves that host", res.PrunedPins)
	}
	if !knownhosts.HostInKnownHosts(filepath.Join(p.SSHDir, "known_hosts"), "github.com") {
		t.Error("a pin another profile still needs was pruned")
	}
	// Keys kept, and said so.
	priv := filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")
	if !onDisk(priv) {
		t.Error("key file deleted without --purge")
	}
	if len(res.KeptFiles) == 0 || !strings.Contains(res.Format(), "--purge") {
		t.Errorf("the summary should say the files are still there and how to remove them:\n%s", res.Format())
	}
}

func TestDeleteProfilePurgeRemovesKeysAndDirectory(t *testing.T) {
	p := fixture(t)
	res, err := New(p, false).DeleteProfile("work", Options{Purge: true})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(p.SSHDir, "profiles", "work")
	for _, rel := range []string{"work_gh-ed25519", "work_gh-ed25519.pub", "work_spare-ed25519", "old/work_gh-ed25519", "old", ""} {
		if onDisk(filepath.Join(dir, rel)) {
			t.Errorf("--purge left %s behind", filepath.Join(dir, rel))
		}
	}
	if len(res.RemovedFiles) == 0 || len(res.RemovedDirs) == 0 {
		t.Errorf("purge should report what it removed: %+v", res)
	}
	// The other profile is untouched.
	if !onDisk(filepath.Join(p.SSHDir, "profiles", "personal", "personal_gh-ed25519")) {
		t.Error("purge crossed profile boundaries")
	}
}

// A purge deletes what sshmgr created. Anything else in the directory is
// somebody's file, so the directory stays and the user is told.
func TestPurgeLeavesUnmanagedFilesAlone(t *testing.T) {
	p := fixture(t)
	stray := filepath.Join(p.SSHDir, "profiles", "work", "notes.txt")
	write(t, stray, "mine\n", 0o600)

	res, err := New(p, false).DeleteProfile("work", Options{Purge: true})
	if err != nil {
		t.Fatal(err)
	}
	if !onDisk(stray) {
		t.Fatal("purge deleted a file sshmgr did not create")
	}
	if !onDisk(filepath.Dir(stray)) {
		t.Error("the directory holding it should have been kept")
	}
	if len(res.UnmanagedLeft) == 0 || !strings.Contains(res.Format(), "did not create") {
		t.Errorf("the summary should explain why the directory survived:\n%s", res.Format())
	}
}

// Deleting the last profile that resolves a hostname does release its pin.
func TestDeleteProfilePrunesPinsNoHostNeeds(t *testing.T) {
	p := fixture(t)
	svc := New(p, false)
	if _, err := svc.DeleteProfile("personal", Options{}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.DeleteProfile("work", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrunedPins != 1 {
		t.Errorf("pruned %d pins, want 1 once no host resolves github.com", res.PrunedPins)
	}
	if knownhosts.HostInKnownHosts(filepath.Join(p.SSHDir, "known_hosts"), "github.com") {
		t.Error("the pin should be gone once nothing references the host")
	}
}

func TestDeleteKeyRefusesWhileAHostUsesIt(t *testing.T) {
	p := fixture(t)
	ref := manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"}
	_, err := New(p, false).DeleteKey(ref, Options{Purge: true})
	if err == nil {
		t.Fatal("deleting a wired key should be refused")
	}
	if !strings.Contains(err.Error(), "gh-work") {
		t.Errorf("the refusal should name the host in the way: %v", err)
	}
	if !onDisk(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")) {
		t.Error("a refused delete must not have touched the key file")
	}
	if _, ok := loadManifest(t, p).KeySpecFor(manifest.KeyRef{Profile: "work", KeyName: "work_spare-ed25519"}); !ok {
		t.Error("a refused delete must not have touched the manifest")
	}
}

func TestDeleteKeyRemovesDeclarationRecordAndFiles(t *testing.T) {
	p := fixture(t)
	ref := manifest.KeyRef{Profile: "work", KeyName: "work_spare-ed25519"}
	priv := filepath.Join(p.SSHDir, "profiles", "work", "work_spare-ed25519")

	// Without --purge: declaration and record go, files stay.
	res, err := New(p, false).DeleteKey(ref, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := loadManifest(t, p)
	if _, ok := m.KeySpecFor(ref); ok {
		t.Error("the declaration should be gone")
	}
	refs, _ := m.KeyRefs()
	for _, r := range refs {
		if r == ref {
			t.Error("the key should no longer be a known key")
		}
	}
	if !onDisk(priv) || len(res.KeptFiles) == 0 {
		t.Error("without --purge the files stay, and the summary says so")
	}
	if len(res.PrunedRecords) != 1 {
		t.Errorf("pruned records = %v, want the one inventory record", res.PrunedRecords)
	}
	// The wired key is untouched by all of this.
	if !onDisk(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")) {
		t.Error("deleting one key removed another")
	}
}

func TestDeleteKeyPurgeRemovesTheFiles(t *testing.T) {
	p := fixture(t)
	ref := manifest.KeyRef{Profile: "work", KeyName: "work_spare-ed25519"}
	priv := filepath.Join(p.SSHDir, "profiles", "work", "work_spare-ed25519")

	res, err := New(p, false).DeleteKey(ref, Options{Purge: true})
	if err != nil {
		t.Fatal(err)
	}
	if onDisk(priv) || onDisk(priv+".pub") {
		t.Error("--purge should have removed both halves of the pair")
	}
	if len(res.RemovedFiles) != 2 {
		t.Errorf("removed %v, want exactly the pair", res.RemovedFiles)
	}
	// The profile is still in use, so its directory must survive the purge.
	if !onDisk(filepath.Join(p.SSHDir, "profiles", "work")) {
		t.Error("purging one key removed the whole profile directory")
	}
}

func TestDeleteUnknownTargets(t *testing.T) {
	p := fixture(t)
	svc := New(p, false)
	if _, err := svc.DeleteProfile("nope", Options{}); err == nil {
		t.Error("deleting an unknown profile should error")
	}
	if _, err := svc.DeleteKey(manifest.KeyRef{Profile: "work", KeyName: "nope"}, Options{}); err == nil {
		t.Error("deleting an undeclared key should error")
	}
}

// Deleting a host has to finish the same way deleting a profile does: the Host
// block goes out of the rendered config immediately, not at the next reconcile.
func TestDeleteHostRerendersAndPrunes(t *testing.T) {
	p := fixture(t)
	// personal is the only other profile resolving github.com; remove it first so
	// the pin genuinely has no host left once gh-work goes.
	if _, err := New(p, false).DeleteProfile("personal", Options{}); err != nil {
		t.Fatal(err)
	}
	res, err := New(p, false).DeleteHost("work", "gh-work", Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatalf("config not re-rendered: %v", err)
	}
	if strings.Contains(string(cfg), "gh-work") {
		t.Errorf("the deleted host's block is still rendered:\n%s", cfg)
	}
	if res.PrunedPins != 1 {
		t.Errorf("pruned %d pins, want 1 once no host resolves github.com", res.PrunedPins)
	}
	// The profile survives, so its directory must too - even though the purge
	// path could have found it empty.
	if !onDisk(filepath.Join(p.SSHDir, "profiles", "work")) {
		t.Error("deleting a host removed its profile's directory")
	}
}

// Three things can become of the key a deleted host used, and the difference
// decides whether --purge may touch its files at all.
func TestDeleteHostClassifiesTheKeyItLeavesBehind(t *testing.T) {
	t.Run("still used by another host: nothing to report", func(t *testing.T) {
		p := fixture(t)
		// Point a second host at work's key, then delete the first.
		addHostToWork(t, p, `{"alias":"gh-alt","hostname":"gitlab.com","user":"git","key_name":"work_gh-ed25519"}`)
		res, err := New(p, false).DeleteHost("work", "gh-work", Options{Purge: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.UnwiredKeys) != 0 || len(res.OrphanedKeys) != 0 {
			t.Errorf("a key another host still uses is not stranded: %+v", res)
		}
		if len(res.RemovedFiles) != 0 {
			t.Error("--purge must not touch a key another host still uses")
		}
		if !onDisk(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")) {
			t.Fatal("a key in use was deleted")
		}
	})

	t.Run("still declared: unwired, and --purge still leaves it", func(t *testing.T) {
		p := fixture(t)
		declareKeyOnWork(t, p, "work_gh-ed25519")
		res, err := New(p, false).DeleteHost("work", "gh-work", Options{Purge: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.UnwiredKeys) != 1 || res.UnwiredKeys[0] != "work/work_gh-ed25519" {
			t.Errorf("unwired keys = %v, want the declared key", res.UnwiredKeys)
		}
		if !onDisk(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")) {
			t.Error("--purge deleted a key the profile still declares")
		}
		for _, want := range []string{"UNWIRED", "key delete work/work_gh-ed25519 --purge", "--key-name work_gh-ed25519"} {
			if !strings.Contains(res.Format(), want) {
				t.Errorf("the summary should offer both ways out, missing %q:\n%s", want, res.Format())
			}
		}
	})

	t.Run("nothing else named it: orphaned, and --purge takes the files", func(t *testing.T) {
		p := fixture(t)
		priv := filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")

		// Without --purge the files stay, and the summary says the key left the
		// manifest - which is the state doctor reports as an orphan.
		res, err := New(p, false).DeleteHost("work", "gh-work", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.OrphanedKeys) != 1 || !onDisk(priv) {
			t.Fatalf("expected an orphaned key still on disk: %+v", res)
		}
		if !strings.Contains(res.Format(), "left the manifest") {
			t.Errorf("the summary should explain what happened:\n%s", res.Format())
		}
	})

	t.Run("orphaned with --purge", func(t *testing.T) {
		p := fixture(t)
		priv := filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")
		res, err := New(p, false).DeleteHost("work", "gh-work", Options{Purge: true})
		if err != nil {
			t.Fatal(err)
		}
		if onDisk(priv) || onDisk(priv+".pub") {
			t.Error("--purge should have removed the orphaned pair")
		}
		// The rotation predecessor in old/ goes with it.
		if onDisk(filepath.Join(p.SSHDir, "profiles", "work", "old", "work_gh-ed25519")) {
			t.Error("--purge left the rotation predecessor behind")
		}
		if len(res.RemovedFiles) != 3 {
			t.Errorf("removed %v, want the pair plus the old/ predecessor", res.RemovedFiles)
		}
		// work still declares work_spare-ed25519, so neither it nor the directory go.
		if !onDisk(filepath.Join(p.SSHDir, "profiles", "work", "work_spare-ed25519")) {
			t.Error("--purge crossed from the deleted host's key to another key")
		}
	})
}

func TestDeleteHostUnknownTargets(t *testing.T) {
	p := fixture(t)
	svc := New(p, false)
	if _, err := svc.DeleteHost("nope", "gh-work", Options{}); err == nil {
		t.Error("an unknown profile should error")
	}
	if _, err := svc.DeleteHost("work", "nope", Options{}); err == nil {
		t.Error("an unknown alias should error")
	}
}

// addHostToWork appends a raw host object to the fixture's work profile, which
// is the first "hosts" array in the manifest.
func addHostToWork(t *testing.T, p paths.Paths, hostJSON string) {
	t.Helper()
	patchManifest(t, p, `"hosts": [`, `"hosts": [`+hostJSON+`,`)
}

// declareKeyOnWork adds a keys entry for an existing key name. work is the only
// profile in the fixture with a keys list.
func declareKeyOnWork(t *testing.T, p paths.Paths, name string) {
	t.Helper()
	patchManifest(t, p, `"keys": [`, `"keys": [{"name": "`+name+`"},`)
}

func patchManifest(t *testing.T, p paths.Paths, needle, replacement string) {
	t.Helper()
	body, err := os.ReadFile(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(body), needle, replacement, 1)
	if patched == string(body) {
		t.Fatalf("fixture manifest does not contain %q", needle)
	}
	write(t, p.Manifest(), patched, 0o600)
	if _, err := manifest.Load(p.Manifest()); err != nil {
		t.Fatalf("patched manifest is invalid: %v", err)
	}
}
