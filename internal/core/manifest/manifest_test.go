package manifest

import (
	"os"
	"path/filepath"
	"strings"
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
		"duplicate alias, same profile": `{"profiles":{"p":{"hosts":[
			{"alias":"gh","hostname":"h1","user":"u"},
			{"alias":"gh","hostname":"h2","user":"u"}
		]}}}`,
		"duplicate alias, across profiles": `{"profiles":{
			"work":{"hosts":[{"alias":"gh","hostname":"h1","user":"u"}]},
			"personal":{"hosts":[{"alias":"gh","hostname":"h2","user":"u"}]}
		}}`,
	}
	for name, js := range cases {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

// Under inline rendering every Host block lives in one file, so a duplicate
// alias is deterministically dead config (ssh takes the first, in manifest
// order) rather than a warning about filesystem-glob ordering. Load must
// refuse it outright.
func TestDuplicateAliasAcrossProfilesIsRejected(t *testing.T) {
	const js = `{"profiles":{
		"work":{"hosts":[{"alias":"gh","hostname":"h1","user":"u"}]},
		"personal":{"hosts":[{"alias":"gh","hostname":"h2","user":"u"}]}
	}}`
	_, err := loadJSON(t, js)
	if err == nil {
		t.Fatal("expected a validation error for a duplicate alias")
	}
	for _, want := range []string{`"gh"`, "personal", "work"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

// A profile models an org and a key file is named for the person using it, so
// the same name legitimately appears in several profiles. The directory keeps
// them apart on disk; commands disambiguate with the profile/key selector.
func TestDuplicateKeyNameAcrossProfilesIsAllowed(t *testing.T) {
	m, err := loadJSON(t, dupKeyManifest)
	if err != nil {
		t.Fatalf("same key_name in two profiles should load: %v", err)
	}
	refs, err := m.KeyRefs()
	if err != nil {
		t.Fatal(err)
	}
	// personal + adelsaiq share the basename; simtabi is a third distinct key.
	if len(refs) != 3 {
		t.Fatalf("KeyRefs = %v, want one entry per distinct profile/key", refs)
	}
	for _, ref := range refs {
		want := "~/.ssh/profiles/" + ref.Profile + "/" + ref.KeyName
		if got := m.IdentityFile(ref.Profile, ref.KeyName); got != want {
			t.Errorf("identity for %s = %q, want %q", ref, got, want)
		}
	}
}

func TestResolveKeySelector(t *testing.T) {
	m, err := loadJSON(t, dupKeyManifest)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("composite form picks the named profile", func(t *testing.T) {
		ref, err := m.ResolveKeySelector("adelsaiq/imani_github-ed25519")
		if err != nil {
			t.Fatal(err)
		}
		if ref.Profile != "adelsaiq" {
			t.Errorf("profile = %q, want adelsaiq", ref.Profile)
		}
	})
	t.Run("bare name resolves when only one profile uses it", func(t *testing.T) {
		ref, err := m.ResolveKeySelector("simtabi_github-ed25519")
		if err != nil {
			t.Fatal(err)
		}
		if ref.String() != "simtabi/simtabi_github-ed25519" {
			t.Errorf("ref = %q", ref)
		}
	})
	t.Run("bare name shared by profiles is ambiguous", func(t *testing.T) {
		_, err := m.ResolveKeySelector("imani_github-ed25519")
		if err == nil {
			t.Fatal("expected an ambiguity error")
		}
		// The message must name the candidates - the caller has to retype one.
		for _, want := range []string{"adelsaiq/imani_github-ed25519", "personal/imani_github-ed25519"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not offer %q", err, want)
			}
		}
	})
	t.Run("rejects unknown key, profile, and pairing", func(t *testing.T) {
		for _, sel := range []string{"", "nope", "nosuch/imani_github-ed25519", "personal/nope"} {
			if _, err := m.ResolveKeySelector(sel); err == nil {
				t.Errorf("selector %q should have failed", sel)
			}
		}
	})
}

// One person (imani) working under two orgs, plus a third profile whose key name
// is unique - enough to exercise both the ambiguous and unambiguous paths.
const dupKeyManifest = `{"profiles":{
	"personal":{"hosts":[{"alias":"github-imani","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]},
	"adelsaiq":{"hosts":[{"alias":"github-danniela","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]},
	"simtabi":{"hosts":[{"alias":"github-simtabi","hostname":"github.com","user":"git","key_name":"simtabi_github-ed25519"}]}}}`

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

// TestSerializationEmitsAllFieldsInFileOrder locks the byte-parity contract with
// pydantic model_dump: unset pointers -> null, no tags -> [], raw_options -> {},
// and profiles in manifest (file) order, not sorted.
func TestSerializationEmitsAllFieldsInFileOrder(t *testing.T) {
	// "work" before "alpha" - a Go map would sort these the other way.
	m, err := loadJSON(t, `{
	  "version": 1,
	  "profiles": {
	    "work": {"key_scope": "per_service", "hosts": [
	      {"alias": "gh", "hostname": "github.com", "user": "git"}
	    ]},
	    "alpha": {"key_scope": "shared", "key_name": "id_a", "hosts": []}
	  }
	}`)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if err := m.Save(out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	for _, want := range []string{
		`"provider": null`, `"token_env": null`, `"tags": []`, `"raw_options": {}`,
		`"vpn_name": null`, `"key_name": null`,
	} {
		if !contains(s, want) {
			t.Errorf("serialized manifest missing %s", want)
		}
	}
	// Profiles must appear in file order: "work" before "alpha".
	wi, ai := index(s, `"work"`), index(s, `"alpha"`)
	if wi < 0 || ai < 0 || wi > ai {
		t.Errorf("profiles not in file order (work before alpha): work@%d alpha@%d", wi, ai)
	}
}

func contains(s, sub string) bool { return index(s, sub) >= 0 }

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
