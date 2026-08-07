package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRecordSerializationMatchesV1 locks in the byte-for-byte serialization
// parity with the serializer v1 and v2 used: unset pointer fields emit null
// (not omitted), and an empty deployments list emits [] (not null/omitted).
func TestRecordSerializationMatchesV1(t *testing.T) {
	b, err := json.Marshal(KeyRecord{Profile: "p", Path: "~/.ssh/profiles/p/k", Type: "ed25519", RotateAfterDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"comment":null`, `"created":null`, `"expires_on":null`, `"deployments":[]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("record JSON missing %s\n got: %s", want, got)
		}
	}
	// Field order matches the model declaration order those versions used.
	wantOrder := []string{"profile", "path", "type", "comment", "created", "rotate_after_days", "expires_on", "deployments"}
	last := -1
	for _, f := range wantOrder {
		i := strings.Index(got, `"`+f+`"`)
		if i <= last {
			t.Errorf("field %q out of order in %s", f, got)
		}
		last = i
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	inv, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || inv == nil || len(inv.Keys) != 0 {
		t.Fatalf("missing inventory should load empty: inv=%v err=%v", inv, err)
	}
}

func TestLoadDefaultsAndForbid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inventory.json")
	_ = os.WriteFile(p, []byte(`{"version":1,"keys":{"SHA256:abc":{
		"profile":"work","path":"~/.ssh/profiles/work/work_hpc-ed25519",
		"created":"2026-01-01","deployments":[{"target":"hpc","method":"ssh-copy-id","verified":true}]}}}`), 0o600)
	inv, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	rec := inv.Keys["SHA256:abc"]
	if rec.Type != "ed25519" || rec.RotateAfterDays != 365 {
		t.Fatalf("defaults not applied: type=%q rotate=%d", rec.Type, rec.RotateAfterDays)
	}
	if rec.NeedsRedeploy() {
		t.Error("a verified deployment means NeedsRedeploy=false")
	}

	// unknown field is rejected
	_ = os.WriteFile(p, []byte(`{"keys":{"k":{"profile":"p","path":"x","bogus":1}}}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Error("unknown field should be rejected")
	}
}

func TestNeedsRedeploy(t *testing.T) {
	none := KeyRecord{Deployments: []Deployment{{Verified: false}}}
	if !none.NeedsRedeploy() {
		t.Error("no verified deployment -> needs redeploy")
	}
	if (KeyRecord{}).NeedsRedeploy() != true {
		t.Error("no deployments -> needs redeploy")
	}
}

func TestIsArchivedPath(t *testing.T) {
	cases := map[string]bool{
		"~/.ssh/profiles/work/old/work_hpc-ed25519": true,
		"~/.ssh/profiles/work/work_hpc-ed25519":     false,
		"~/.ssh/profiles/old/old_box-ed25519":       false, // profile literally named "old"
		"profiles/dev/old/k":                        true,
	}
	for p, want := range cases {
		if got := IsArchivedPath(p); got != want {
			t.Errorf("IsArchivedPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestComputeExpiry(t *testing.T) {
	got, err := ComputeExpiry("2026-01-01", 365)
	if err != nil || got != "2027-01-01" {
		t.Fatalf("ComputeExpiry = %q, %v; want 2027-01-01", got, err)
	}
	if _, err := ComputeExpiry("not-a-date", 30); err == nil {
		t.Error("a malformed date should error")
	}
	if len(Today()) != 10 {
		t.Errorf("Today() = %q, want YYYY-MM-DD", Today())
	}
}

// Both files claimed atomic persistence in their package docs and used
// os.WriteFile, which truncates first. A crash mid-write left a truncated
// inventory - the only record of every key's expiry and deployments - and
// WriteFile also kept whatever mode the file already had.
func TestSaveIsAtomicAndReassertsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")

	inv := New()
	created := "2026-01-01"
	inv.Record("SHA256:one", KeyRecord{Profile: "work", Path: "~/.ssh/profiles/work/k", Created: &created})
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}
	// Loosen the mode the way an errant umask or a restore would.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	inv.Record("SHA256:two", KeyRecord{Profile: "work", Path: "~/.ssh/profiles/work/k2"})
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}
	// Windows has no mode bits to reassert - permissions there are ACLs, which
	// internal/util/perms handles separately. The atomicity half below is the
	// part that applies everywhere.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o after save, want 600", fi.Mode().Perm())
		}
	}
	// No temp file left beside it, and the content is complete.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("save left residue: %v", entries)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatalf("saved inventory does not load: %v", err)
	}
	if len(back.Keys) != 2 {
		t.Errorf("round trip lost records: %+v", back.Keys)
	}
}

// Round-tripping the shipped inventory: what Save writes, Load reads back
// identically, and a second Save is byte-stable. This is the property the
// atomic-write change relies on - a rewritten file must be the same file.
func TestSaveLoadRoundTripIsStable(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.json")

	inv := New()
	created, expires, comment := "2026-01-01", "2027-01-01", "work/gh 2026-01-01"
	date := "2026-02-02"
	inv.Record("SHA256:one", KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519",
		Comment: &comment, Created: &created, RotateAfterDays: 365, ExpiresOn: &expires,
		Deployments: []Deployment{
			{Target: "gh", Method: "github-gh", Date: &date, Verified: true},
			{Target: "box", Method: "manual", Verified: false},
		},
	})
	inv.Record("SHA256:two", KeyRecord{Profile: "home", Path: "~/.ssh/profiles/home/k"})

	if err := inv.Save(first); err != nil {
		t.Fatal(err)
	}
	back, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Keys) != 2 {
		t.Fatalf("round trip lost records: %+v", back.Keys)
	}
	rec := back.Keys["SHA256:one"]
	if rec.Comment == nil || *rec.Comment != comment {
		t.Errorf("comment lost: %v", rec.Comment)
	}
	if len(rec.Deployments) != 2 || rec.Deployments[0].Target != "gh" || !rec.Deployments[0].Verified {
		t.Errorf("deployments lost or reordered: %+v", rec.Deployments)
	}
	if rec.Deployments[1].Date != nil {
		t.Errorf("an unset deployment date should stay unset, got %v", rec.Deployments[1].Date)
	}

	second := filepath.Join(dir, "b.json")
	if err := back.Save(second); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("save is not byte-stable across a round trip:\n--- first ---\n%s\n--- second ---\n%s", a, b)
	}
}

// Record replaces rather than accumulating: minting a key twice under the same
// fingerprint must not leave two entries claiming the same path.
func TestRecordReplacesAnExistingFingerprint(t *testing.T) {
	inv := New()
	inv.Record("SHA256:x", KeyRecord{Profile: "a", Path: "/p/one"})
	inv.Record("SHA256:x", KeyRecord{Profile: "b", Path: "/p/two"})

	if len(inv.Keys) != 1 {
		t.Fatalf("got %d records, want 1", len(inv.Keys))
	}
	if inv.Keys["SHA256:x"].Path != "/p/two" {
		t.Errorf("path = %q, want the later record", inv.Keys["SHA256:x"].Path)
	}
}

// A deployment counts only when verified. A manual paste is recorded so the
// attempt is visible, but it does not clear needs-redeploy.
func TestNeedsRedeployTurnsOnVerifiedOnly(t *testing.T) {
	cases := map[string]struct {
		deps []Deployment
		want bool
	}{
		"none":                {nil, true},
		"one unverified":      {[]Deployment{{Target: "a"}}, true},
		"several unverified":  {[]Deployment{{Target: "a"}, {Target: "b"}}, true},
		"one verified":        {[]Deployment{{Target: "a", Verified: true}}, false},
		"mixed, one verified": {[]Deployment{{Target: "a"}, {Target: "b", Verified: true}}, false},
	}
	for name, c := range cases {
		if got := (KeyRecord{Deployments: c.deps}).NeedsRedeploy(); got != c.want {
			t.Errorf("%s: NeedsRedeploy = %v, want %v", name, got, c.want)
		}
	}
}

// ComputeExpiry is plain date arithmetic, but it decides when a key is reported
// overdue, so the leap-year and zero cases are worth pinning.
// v1's inventory (compute_expiry).
func TestComputeExpiryArithmetic(t *testing.T) {
	cases := []struct {
		created string
		days    int
		want    string
	}{
		{"2026-01-01", 365, "2027-01-01"},
		{"2024-01-01", 365, "2024-12-31"}, // 2024 is a leap year
		{"2026-01-01", 0, "2026-01-01"},   // no rotation window: due immediately
		{"2026-12-31", 1, "2027-01-01"},   // year boundary
		{"2026-02-28", 1, "2026-03-01"},   // non-leap February
		{"2024-02-28", 1, "2024-02-29"},   // leap February
	}
	for _, c := range cases {
		got, err := ComputeExpiry(c.created, c.days)
		if err != nil {
			t.Errorf("ComputeExpiry(%q,%d): %v", c.created, c.days, err)
			continue
		}
		if got != c.want {
			t.Errorf("ComputeExpiry(%q,%d) = %q, want %q", c.created, c.days, got, c.want)
		}
	}
	for _, bad := range []string{"", "2026-13-01", "01/01/2026", "2026-01-01T00:00:00Z"} {
		if _, err := ComputeExpiry(bad, 30); err == nil {
			t.Errorf("ComputeExpiry(%q) should have errored", bad)
		}
	}
}

// A corrupt inventory is an error, not an empty one. Silently starting over
// would drop every deployment record the user has.
func TestCorruptInventoryIsAnErrorNotAFreshStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	for _, corrupt := range []string{"{", "not json at all", `{"keys":"not-an-object"}`, ""} {
		if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("a corrupt inventory (%q) loaded as if it were fine", corrupt)
		}
	}
}
