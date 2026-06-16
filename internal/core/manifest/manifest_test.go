package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// loadJSON writes s to a temp manifest and loads it.
func loadJSON(t *testing.T, s string) (*Manifest, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadRealManifest(t *testing.T) {
	m, err := Load("../../../config/manifest.json")
	if err != nil {
		t.Fatalf("load shipped manifest: %v", err)
	}
	if m.Version != 1 || m.Defaults.KeyType != "ed25519" {
		t.Fatalf("defaults wrong: version=%d key_type=%q", m.Version, m.Defaults.KeyType)
	}
	// JSON number coerced to string, matching Python str(60).
	if got := m.Defaults.GlobalOptions.Get("ServerAliveInterval"); got != "60" {
		t.Fatalf("ServerAliveInterval = %q, want \"60\"", got)
	}
	if !m.Defaults.ExpiryCheck.Enabled || m.Defaults.ExpiryCheck.DebounceHours != 24 {
		t.Fatal("expiry_check defaults not applied")
	}
	resolved, err := m.IterResolved()
	if err != nil {
		t.Fatalf("IterResolved: %v", err)
	}
	if len(resolved) != 6 { // 4 dev/personal/simtabi/work hosts; school is empty
		t.Fatalf("resolved count = %d, want 6", len(resolved))
	}
	byKey := map[string]string{}
	for _, r := range resolved {
		byKey[r.KeyName] = r.IdentityFile
	}
	want := map[string]string{
		"work_unc-ed25519":                  "~/.ssh/profiles/work/work_unc-ed25519",
		"personal_github-ed25519":           "~/.ssh/profiles/personal/personal_github-ed25519",
		"development_oribi-db-psql-ed25519": "~/.ssh/profiles/development/development_oribi-db-psql-ed25519",
	}
	for k, v := range want {
		if byKey[k] != v {
			t.Errorf("identity_file[%s] = %q, want %q", k, byKey[k], v)
		}
	}
	if got := m.NonEmptyProfiles(); len(got) != 4 {
		t.Errorf("NonEmptyProfiles = %v, want 4 (school excluded)", got)
	}
}

func TestValidationRejections(t *testing.T) {
	cases := map[string]string{
		"unknown field":     `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u","bogus":1}]}}}`,
		"dangerous opt":     `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u","raw_options":{"ProxyCommand":"x"}}]}}}`,
		"unsafe alias":      `{"profiles":{"p":{"hosts":[{"alias":"a/b","hostname":"h","user":"u"}]}}}`,
		"glob alias":        `{"profiles":{"p":{"hosts":[{"alias":"*","hostname":"h","user":"u"}]}}}`,
		"leading-dash user": `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"-x"}]}}}`,
		"bad key_scope":     `{"profiles":{"p":{"key_scope":"weird","hosts":[]}}}`,
		"dup key_name across profiles": `{"profiles":{
			"p1":{"key_scope":"shared","key_name":"deploy","hosts":[{"alias":"a","hostname":"h","user":"u"}]},
			"p2":{"key_scope":"shared","key_name":"deploy","hosts":[{"alias":"b","hostname":"h","user":"u"}]}}}`,
	}
	for name, js := range cases {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

func TestSharedAndPerServiceResolution(t *testing.T) {
	m, err := loadJSON(t, `{"profiles":{"team":{"key_scope":"shared","key_name":"team_all-ed25519",
		"hosts":[{"alias":"a","hostname":"h1","user":"u"},{"alias":"b","hostname":"h2","user":"u"}]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.IterResolved()
	if err != nil {
		t.Fatal(err)
	}
	for _, rk := range r { // both hosts share the one key
		if rk.KeyName != "team_all-ed25519" {
			t.Errorf("shared host key = %q, want team_all-ed25519", rk.KeyName)
		}
	}
	// per_service with no explicit key_name derives from profile+alias
	m2, _ := loadJSON(t, `{"profiles":{"work":{"hosts":[{"alias":"sc.its.unc.edu","hostname":"h","user":"u"}]}}}`)
	r2, _ := m2.IterResolved()
	if r2[0].KeyName != "work_sc-its-unc-edu-ed25519" {
		t.Errorf("derived key = %q, want work_sc-its-unc-edu-ed25519", r2[0].KeyName)
	}
}
