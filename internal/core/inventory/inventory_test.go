package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecordSerializationMatchesPydantic locks in the byte-for-byte serialization
// parity with pydantic's model_dump(mode="json"): unset pointer fields emit null
// (not omitted), and an empty deployments list emits [] (not null/omitted).
func TestRecordSerializationMatchesPydantic(t *testing.T) {
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
	// Field order matches the pydantic model declaration order.
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
	os.WriteFile(p, []byte(`{"version":1,"keys":{"SHA256:abc":{
		"profile":"work","path":"~/.ssh/profiles/work/work_unc-ed25519",
		"created":"2026-01-01","deployments":[{"target":"unc","method":"ssh-copy-id","verified":true}]}}}`), 0o600)
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
	os.WriteFile(p, []byte(`{"keys":{"k":{"profile":"p","path":"x","bogus":1}}}`), 0o600)
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
		"~/.ssh/profiles/work/old/work_unc-ed25519": true,
		"~/.ssh/profiles/work/work_unc-ed25519":     false,
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
