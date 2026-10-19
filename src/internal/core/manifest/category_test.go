package manifest

import (
	"encoding/json"
	"os"
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

func TestGlobProfileTreeSeesBothLayoutsAndNotArchives(t *testing.T) {
	ssh := t.TempDir()
	for _, rel := range []string{
		"profiles/work/a.pub",                 // flat
		"profiles/work/old/a.pub",             // flat archive - not a category
		"profiles/work/.staging/a.pub",        // flat staging - not a category
		"profiles/clients/adelsaiq/b.pub",     // categorized
		"profiles/clients/adelsaiq/old/b.pub", // categorized archive - too deep
	} {
		p := filepath.Join(ssh, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rels := func(paths []string) string {
		var out []string
		for _, p := range paths {
			r, _ := filepath.Rel(ssh, p)
			out = append(out, filepath.ToSlash(r))
		}
		return strings.Join(out, ",")
	}
	if got, want := rels(GlobProfileTree(ssh, "*.pub")), "profiles/clients/adelsaiq/b.pub,profiles/work/a.pub"; got != want {
		t.Errorf("*.pub = %s, want %s", got, want)
	}
	if got, want := rels(GlobProfileTree(ssh, "old")), "profiles/clients/adelsaiq/old,profiles/work/old"; got != want {
		t.Errorf("old = %s, want %s", got, want)
	}
}

func TestKeyStoreValidation(t *testing.T) {
	bad := map[string]string{
		"unknown store":       `{"version":1,"profiles":{"p":{"key_store":"vault","hosts":[]}}}`,
		"1password, no vault": `{"version":1,"profiles":{"p":{"key_store":"1password","hosts":[]}}}`,
		"vault without store": `{"version":1,"profiles":{"p":{"op_vault":"Simtabi","hosts":[]}}}`,
	}
	for name, doc := range bad {
		if _, err := loadJSON(t, doc); err == nil {
			t.Errorf("%s: loaded, want a validation error", name)
		}
	}
	m, err := loadJSON(t, `{"version":1,"profiles":{"bot":{"key_store":"1password","op_vault":"Simtabi","hosts":[]},"f":{"hosts":[]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Profiles["bot"].InOnePassword() || m.Profiles["f"].InOnePassword() || !UsesOnePassword(m) {
		t.Error("InOnePassword / UsesOnePassword disagree with the manifest")
	}
	if got := m.IdentityFile("bot", "k"); got != "~/.ssh/profiles/bot/k" {
		t.Errorf("IdentityFile = %q: the key's identity must not change with its store", got)
	}
}

func TestOnePasswordAgentSocketPerPlatform(t *testing.T) {
	cases := map[string]string{
		"darwin":  "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
		"linux":   "~/.1password/agent.sock",
		"freebsd": "~/.1password/agent.sock",
		"windows": "",
	}
	for goos, want := range cases {
		if got := onePasswordAgentFor(goos); got != want {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
	m, _ := loadJSON(t, `{"version":1,"defaults":{"onepassword_agent":"~/.1password/agent.sock"},"profiles":{}}`)
	if got := m.Defaults.OnePasswordAgentSocket(); got != "~/.1password/agent.sock" {
		t.Errorf("override ignored: %q", got)
	}
}
