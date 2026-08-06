package keyaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "keys": [{"name": "work_spare-ed25519"}],
      "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git", "key_name": "work_gh-ed25519"}]}
  }
}`

type fixture struct {
	svc *Service
	ssh string
	inv *inventory.Inventory
}

// hostOnlyManifestJSON has no declared keys, so a tree built from it can have
// exactly one defect at a time.
const hostOnlyManifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git", "key_name": "work_gh-ed25519"}]}
  }
}`

// newFixture builds a tree where only work/work_gh-ed25519 is healthy; each test
// adds the one defect it is about.
func newFixture(t *testing.T) fixture { return newFixtureFrom(t, manifestJSON) }

func newFixtureFrom(t *testing.T, manifestBody string) fixture {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestBody), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	inv := inventory.New()
	f := fixture{ssh: ssh, inv: inv}
	f.writeKey(t, "work", "work_gh-ed25519", true)
	f.record(t, "SHA256:gh", "~/.ssh/profiles/work/work_gh-ed25519")
	if len(m.Profiles["work"].Keys) > 0 {
		// The declared spare exists as a pair too, so it is only ever "unwired".
		f.writeKey(t, "work", "work_spare-ed25519", true)
		f.record(t, "SHA256:spare", "~/.ssh/profiles/work/work_spare-ed25519")
	}
	f.svc = New(&m, inv, ssh)
	return f
}

func (f fixture) writeKey(t *testing.T, profile, name string, withPub bool) {
	t.Helper()
	dir := filepath.Join(f.ssh, "profiles", profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withPub {
		body := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample " + name + "\n"
		if err := os.WriteFile(filepath.Join(dir, name+".pub"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (f fixture) record(t *testing.T, fp, path string) {
	t.Helper()
	created, expires := "2026-01-01", "2027-01-01"
	f.inv.Record(fp, inventory.KeyRecord{
		Profile: "work", Path: path, Type: "ed25519",
		Created: &created, ExpiresOn: &expires, RotateAfterDays: 365,
	})
}

func audit(t *testing.T, f fixture, strict bool) Report {
	t.Helper()
	rep, err := f.svc.Audit(strict)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func subjects(rep Report, state string) []string {
	var out []string
	for _, f := range rep.ByState(state) {
		out = append(out, f.Subject)
	}
	return out
}

// The baseline tree has exactly one defect - the declared spare no host uses -
// which is also the state nothing in the tool noticed before.
func TestBaselineFindsOnlyTheUnwiredKey(t *testing.T) {
	rep := audit(t, newFixture(t), false)
	if got := subjects(rep, Unwired); len(got) != 1 || got[0] != "work/work_spare-ed25519" {
		t.Fatalf("unwired = %v, want the declared spare", got)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("findings = %+v, want only the unwired key", rep.Findings)
	}
	if rep.OK() {
		t.Error("unwired is a blocking state, so the audit should not be OK")
	}
	if !strings.Contains(strings.Join(rep.Lines(), "\n"), "host edit") {
		t.Errorf("an unwired key should carry the command that wires it:\n%s",
			strings.Join(rep.Lines(), "\n"))
	}
}

// The regression that matters most: doctor's orphan check skipped any private
// key with no .pub, so the most dangling artifact possible was invisible.
func TestPrivateKeyWithNoPubIsFound(t *testing.T) {
	f := newFixture(t)
	f.writeKey(t, "work", "work_stray-ed25519", false) // private only, undeclared

	rep := audit(t, f, false)
	if got := subjects(rep, Untracked); len(got) != 1 || got[0] != "profiles/work/work_stray-ed25519" {
		t.Fatalf("untracked = %v, want the stray private key", got)
	}
	if rep.OK() {
		t.Error("an untracked key must fail the audit")
	}
}

func TestUntrackedCoversAWholeUnknownProfile(t *testing.T) {
	f := newFixture(t)
	f.writeKey(t, "ghost", "ghost_old-ed25519", true)

	rep := audit(t, f, false)
	if got := subjects(rep, Untracked); len(got) != 1 || got[0] != "profiles/ghost/ghost_old-ed25519" {
		t.Fatalf("untracked = %v, want the key in the unknown profile", got)
	}
	// A pair yields one finding, not one per file.
	if n := len(rep.ByState(Untracked)); n != 1 {
		t.Errorf("a pair should be one finding, got %d", n)
	}
	if d := rep.ByState(Untracked)[0].Detail; !strings.Contains(d, "ghost") {
		t.Errorf("the detail should name the unknown profile: %q", d)
	}
}

func TestHalfPairAndMissingAreDistinct(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.ssh, "profiles", "work", "work_gh-ed25519.pub")); err != nil {
		t.Fatal(err)
	}
	rep := audit(t, f, false)
	if got := subjects(rep, HalfPair); len(got) != 1 || got[0] != "work/work_gh-ed25519" {
		t.Fatalf("half-pair = %v", got)
	}
	if len(rep.ByState(Missing)) != 0 {
		t.Error("half a pair is not missing")
	}

	// Remove the other half too: now it is missing, and no longer half a pair.
	if err := os.Remove(filepath.Join(f.ssh, "profiles", "work", "work_gh-ed25519")); err != nil {
		t.Fatal(err)
	}
	rep = audit(t, f, false)
	if got := subjects(rep, Missing); len(got) != 1 || got[0] != "work/work_gh-ed25519" {
		t.Fatalf("missing = %v", got)
	}
	if len(rep.ByState(HalfPair)) != 0 {
		t.Error("a key with neither half is missing, not half-paired")
	}
}

// Missing is the normal state between `host add` and the reconcile that mints
// the key, so it must warn rather than fail - otherwise doctor is red during
// ordinary work.
func TestMissingWarnsButStrictFails(t *testing.T) {
	// A tree straight after `host add`: the Host block is rendered, the key it
	// names has not been minted yet. That is ordinary, so doctor must not go red.
	f := newFixtureFrom(t, hostOnlyManifestJSON)
	for _, name := range []string{"work_gh-ed25519", "work_gh-ed25519.pub"} {
		if err := os.Remove(filepath.Join(f.ssh, "profiles", "work", name)); err != nil {
			t.Fatal(err)
		}
	}
	rep := audit(t, f, false)
	if len(rep.Findings) != 1 || rep.Findings[0].State != Missing {
		t.Fatalf("expected exactly one missing key, got %+v", rep.Findings)
	}
	if Blocking(Missing) {
		t.Error("missing must not be a blocking state")
	}
	if !rep.OK() {
		t.Error("a tree whose only fault is an unminted key should still pass")
	}
	if rep.Findings[0].Fix != "sshmgr reconcile" {
		t.Errorf("missing should point at the command that mints it: %q", rep.Findings[0].Fix)
	}
	if audit(t, f, true).OK() {
		t.Error("--strict should fail on any finding, including missing")
	}
}

func TestUnrecordedIsFoundWhenTheInventoryForgets(t *testing.T) {
	f := newFixture(t)
	delete(f.inv.Keys, "SHA256:gh")

	rep := audit(t, f, false)
	if got := subjects(rep, Unrecorded); len(got) != 1 || got[0] != "work/work_gh-ed25519" {
		t.Fatalf("unrecorded = %v", got)
	}
	if rep.OK() != false { // the fixture's unwired key also fails it
		t.Error("expected a not-OK report")
	}
}

// A record pointing at a key nothing owns tracks the expiry of something gone -
// but a key the manifest owns and disk lacks is Missing, and reporting it as
// both would double-count the same key.
func TestStaleInventoryExcludesMissingAndArchived(t *testing.T) {
	f := newFixture(t)
	f.record(t, "SHA256:ghost", "~/.ssh/profiles/deleted/deleted_key-ed25519")
	f.record(t, "SHA256:old", "~/.ssh/profiles/work/old/work_gh-ed25519")

	rep := audit(t, f, false)
	if got := subjects(rep, StaleInventory); len(got) != 1 || got[0] != "SHA256:ghost" {
		t.Fatalf("stale-inventory = %v, want only the record for a deleted profile", got)
	}
	if Blocking(StaleInventory) {
		t.Error("a stale record is worth reporting, not failing on")
	}

	// Delete a key the manifest still owns: Missing, never stale-inventory.
	for _, name := range []string{"work_gh-ed25519", "work_gh-ed25519.pub"} {
		if err := os.Remove(filepath.Join(f.ssh, "profiles", "work", name)); err != nil {
			t.Fatal(err)
		}
	}
	rep = audit(t, f, false)
	for _, s := range subjects(rep, StaleInventory) {
		if s == "SHA256:gh" {
			t.Error("a key the manifest owns is Missing, not stale-inventory")
		}
	}
	if len(rep.ByState(Missing)) != 1 {
		t.Errorf("expected the deleted key to be missing: %+v", rep.Findings)
	}
}

// Loose keys are the ones the user already had. They are found without reading
// any private key, and never proposed for deletion.
func TestLooseKeysInSSHDirAreReportedNotTouched(t *testing.T) {
	f := newFixture(t)
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample imani@laptop\n"
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(f.ssh, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("id_ed25519", "PRIVATE\n")
	write("id_ed25519.pub", pub)
	write("orphan_key.pub", pub) // a .pub with no private half
	write("config", "Host *\n")  // managed, never a key
	write("known_hosts", "github.com ssh-ed25519 AAAA\n")
	write("notes.txt", "not a key\n")

	rep := audit(t, f, false)
	got := subjects(rep, Loose)
	want := []string{"id_ed25519", "orphan_key"}
	if len(got) != len(want) {
		t.Fatalf("loose = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("loose[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if Blocking(Loose) {
		t.Error("a key the tool did not create must not fail the audit")
	}
	if fix := rep.ByState(Loose)[0].Fix; !strings.Contains(fix, "import") {
		t.Errorf("a loose key should be offered to import, got %q", fix)
	}
	// Nothing was deleted.
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "orphan_key.pub", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(f.ssh, name)); err != nil {
			t.Errorf("the audit removed %s: %v", name, err)
		}
	}
}

func TestFindingsAreGroupedBySeverityAndStable(t *testing.T) {
	f := newFixture(t)
	f.writeKey(t, "ghost", "ghost_b-ed25519", true)
	f.writeKey(t, "ghost", "ghost_a-ed25519", true)
	f.record(t, "SHA256:ghost", "~/.ssh/profiles/deleted/deleted_key-ed25519")

	first := audit(t, f, false)
	var states []string
	for _, fnd := range first.Findings {
		states = append(states, fnd.State)
	}
	want := []string{Untracked, Untracked, Unwired, StaleInventory}
	if strings.Join(states, ",") != strings.Join(want, ",") {
		t.Errorf("states = %v, want %v (worst first)", states, want)
	}
	if got := subjects(first, Untracked); got[0] > got[1] {
		t.Errorf("findings within a state should sort: %v", got)
	}
	// The inventory is a map, so a second run must not reorder anything.
	second := audit(t, f, false)
	if strings.Join(second.Lines(), "\n") != strings.Join(first.Lines(), "\n") {
		t.Error("two audits of the same tree reported differently")
	}
	if s := first.Summary(); s != "untracked=2 unwired=1 stale-inventory=1" {
		t.Errorf("summary = %q", s)
	}
}

// Notes decides which states a key is in; manifestKeyFinding turns each into the
// row a user reads. They are two switches over the same vocabulary, so adding a
// state to one and not the other yields a finding with no explanation and no fix
// - which reads as "something is wrong with this key" and nothing more.
func TestEveryStateAKeyCanBeInCarriesADetailAndAFix(t *testing.T) {
	const j = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service",
	    "keys":[{"name":"work_unwired-ed25519"},{"name":"work_halfpriv-ed25519"},
	            {"name":"work_halfpub-ed25519"},{"name":"work_gone-ed25519"}],
	    "hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	dir := filepath.Join(ssh, "profiles", "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	put := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("work_gh-ed25519", "PRIVATE\n") // wired, unrecorded
	put("work_gh-ed25519.pub", "ssh-ed25519 A gh\n")
	put("work_unwired-ed25519", "PRIVATE\n")
	put("work_unwired-ed25519.pub", "ssh-ed25519 A u\n")
	put("work_halfpriv-ed25519", "PRIVATE\n")            // private only
	put("work_halfpub-ed25519.pub", "ssh-ed25519 A h\n") // pub only
	// work_gone-ed25519: neither half.

	rep, err := New(&m, inventory.New(), ssh).Audit(false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if !strings.Contains(f.Subject, "/") || strings.Contains(f.Subject, "profiles/") {
			continue // tree-level findings; these come from the other walkers
		}
		seen[f.State] = true
		if f.Detail == "" {
			t.Errorf("%s finding for %s has no explanation", f.State, f.Subject)
		}
		if f.Fix == "" {
			t.Errorf("%s finding for %s offers no fix", f.State, f.Subject)
		}
	}
	// Every state a manifest key can be in was actually produced, so an empty
	// switch case could not slip through as "not exercised".
	for _, state := range []string{Missing, HalfPair, Unrecorded, Unwired} {
		if !seen[state] {
			t.Errorf("the fixture did not produce a %s finding; the check is weaker than it looks", state)
		}
	}

	// A half pair names the half that is missing - the two directions need
	// opposite advice, and getting it backwards sends the user to regenerate the
	// key they still have.
	for _, f := range rep.ByState(HalfPair) {
		switch f.Subject {
		case "work/work_halfpriv-ed25519":
			if !strings.Contains(f.Detail, ".pub is missing") {
				t.Errorf("%s: detail = %q, want it to name the missing .pub", f.Subject, f.Detail)
			}
		case "work/work_halfpub-ed25519":
			if !strings.Contains(f.Detail, "private key is missing") {
				t.Errorf("%s: detail = %q, want it to name the missing private key", f.Subject, f.Detail)
			}
		}
	}
}
