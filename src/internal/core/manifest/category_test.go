package manifest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const categorizedManifest = `{
  "version": 1,
  "profiles": {
    "personal": {"category": "internal", "hosts": [
      {"alias": "github-imani", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "adelsaiq": {"category": "clients", "hosts": [
      {"alias": "github-danniela", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "simtabi": {"category": "internal", "hosts": [
      {"alias": "github-simtabi", "hostname": "github.com", "user": "git", "key_name": "simtabi_github-ed25519"}]},
    "legacy": {"hosts": [
      {"alias": "box", "hostname": "box.example", "user": "me", "key_name": "legacy-ed25519"}]}
  }
}`

func TestCategorizedProfilesResolveOneDirectoryDeeper(t *testing.T) {
	m, err := loadJSON(t, categorizedManifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ profile, key, want string }{
		{"personal", "imani_github-ed25519", "~/.ssh/profiles/internal/personal/imani_github-ed25519"},
		{"adelsaiq", "imani_github-ed25519", "~/.ssh/profiles/clients/adelsaiq/imani_github-ed25519"},
		// No category: the flat layout every pre-category manifest relies on.
		{"legacy", "legacy-ed25519", "~/.ssh/profiles/legacy/legacy-ed25519"},
		// Undeclared profile: flat, never a panic or an empty segment.
		{"ghost", "k", "~/.ssh/profiles/ghost/k"},
	}
	for _, c := range cases {
		if got := m.IdentityFile(c.profile, c.key); got != c.want {
			t.Errorf("IdentityFile(%s, %s) = %q, want %q", c.profile, c.key, got, c.want)
		}
	}
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	got := m.KeyPath(sshDir, KeyRef{Profile: "adelsaiq", KeyName: "imani_github-ed25519"})
	want := filepath.Join(sshDir, "profiles", "clients", "adelsaiq", "imani_github-ed25519")
	if got != want {
		t.Errorf("KeyPath = %q, want %q", got, want)
	}
}

func TestCategoriesAreDistinctInFileOrder(t *testing.T) {
	m, err := loadJSON(t, categorizedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Categories(), ","); got != "internal,clients" {
		t.Errorf("Categories = %q, want internal,clients", got)
	}
}

func TestCategoryRoundTripsAndStaysAbsentWhenUnset(t *testing.T) {
	m, err := loadJSON(t, categorizedManifest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m.Profiles["personal"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `{"category":"internal",`) {
		t.Errorf("categorized profile marshals as %s", b)
	}
	b, _ = json.Marshal(m.Profiles["legacy"])
	if strings.Contains(string(b), "category") {
		t.Errorf("uncategorized profile must not grow a category key: %s", b)
	}
}

func TestCategoryValidation(t *testing.T) {
	bad := map[string]string{
		"unsafe segment": `{"version":1,"profiles":{"p":{"category":"../x","hosts":[]}}}`,
		"slash":          `{"version":1,"profiles":{"p":{"category":"a/b","hosts":[]}}}`,
		"clashes with an uncategorized profile": `{"version":1,"profiles":{
			"clients":{"hosts":[]},
			"adelsaiq":{"category":"clients","hosts":[]}}}`,
		"profile named config": `{"version":1,"profiles":{"config":{"category":"internal","hosts":[]}}}`,
	}
	for name, doc := range bad {
		if _, err := loadJSON(t, doc); err == nil {
			t.Errorf("%s: manifest loaded, want a validation error", name)
		}
	}
	// A category may share its name with a profile that is itself in a category:
	// profiles/internal/internal/ is unambiguous.
	ok := `{"version":1,"profiles":{"internal":{"category":"internal","hosts":[]}}}`
	if _, err := loadJSON(t, ok); err != nil {
		t.Errorf("self-named categorized profile rejected: %v", err)
	}
}
