package providers

import (
	"os"
	"testing"
)

// TestEmbeddedCatalogMatchesRepo enforces the invariant that the embedded default
// is byte-identical to config/providers.json (as Python keeps data/providers.json).
func TestEmbeddedCatalogMatchesRepo(t *testing.T) {
	repo, err := os.ReadFile("../../../config/providers.json")
	if err != nil {
		t.Fatalf("read repo catalog: %v", err)
	}
	if string(repo) != string(defaultCatalog) {
		t.Error("embedded default_providers.json drifted from config/providers.json")
	}
}

// TestCategoryOf covers the catalog categories and the unknown/empty fallback.
func TestCategoryOf(t *testing.T) {
	cases := map[string]string{
		"github":         "vcs",
		"gitlab":         "vcs",
		"bitbucket":      "vcs", // catalog-only (not a built-in)
		"digitalocean":   "vps",
		"ploi":           "panel",
		"generic-ssh":    "server",
		"manual":         "generic",
		"":               "server", // none -> generic-ssh fallback
		"does-not-exist": "server",
	}
	for name, want := range cases {
		if got := CategoryOf(name, ""); got != want {
			t.Errorf("CategoryOf(%q)=%q want %q", name, got, want)
		}
	}
}

// TestResolvedKeysURL covers explicit override, derived-from-host, and derived
// host-independent URLs.
func TestResolvedKeysURL(t *testing.T) {
	specs := AllSpecs("")
	cases := map[string]string{
		"github":         "https://github.com/settings/keys",
		"gitlab":         "https://gitlab.com/-/user_settings/ssh_keys",
		"bitbucket":      "https://bitbucket.org/account/settings/ssh-keys/",
		"aws-codecommit": "https://console.aws.amazon.com/iam/home#/security_credentials",
		"ploi":           "https://ploi.io/servers", // explicit manage_url
	}
	for name, want := range cases {
		s, ok := specs[name]
		if !ok {
			t.Errorf("spec %q missing", name)
			continue
		}
		if got := s.ResolvedKeysURL(); got != want {
			t.Errorf("%s.ResolvedKeysURL()=%q want %q", name, got, want)
		}
	}
}

// TestListAndCredentialPresence covers sorting, category/kind, and live token
// presence via an injected getenv.
func TestListAndCredentialPresence(t *testing.T) {
	env := map[string]string{"GH_TOKEN": "x", "GLAB_TOKEN": ""} // set / empty / unset
	getenv := func(k string) string { return env[k] }
	infos := List("", getenv)

	if len(infos) == 0 {
		t.Fatal("no providers listed")
	}
	// Sorted by name.
	for i := 1; i < len(infos); i++ {
		if infos[i-1].Name > infos[i].Name {
			t.Fatalf("not sorted at %d: %q > %q", i, infos[i-1].Name, infos[i].Name)
		}
	}
	by := map[string]Info{}
	for _, i := range infos {
		by[i.Name] = i
	}
	if g := by["github"]; g.Category != "vcs" || g.TokenEnv != "GH_TOKEN" || !g.TokenPresent {
		t.Errorf("github: %+v (want vcs/GH_TOKEN/present)", g)
	}
	if g := by["gitlab"]; g.TokenPresent { // env value is empty -> not present
		t.Errorf("gitlab credential should be absent (empty env): %+v", g)
	}
	if d := by["digitalocean"]; d.TokenPresent { // unset -> not present
		t.Errorf("digitalocean credential should be absent (unset env): %+v", d)
	}
	if m := by["manual"]; m.TokenEnv != "" || m.TokenPresent { // no token at all
		t.Errorf("manual should have no token: %+v", m)
	}
}

func TestDefaultCatalogIsEmbedded(t *testing.T) {
	if string(DefaultCatalog()) != string(defaultCatalog) {
		t.Error("DefaultCatalog should return the embedded bytes")
	}
}

// TestUserFileOverridesAndTolerance: a user providers.json overrides built-ins and
// adds entries; a malformed entry is skipped, not fatal.
func TestUserFileOverridesAndTolerance(t *testing.T) {
	dir := t.TempDir()
	f := dir + "/providers.json"
	body := `{"providers":{
	  "github": {"category":"panel","kind":"web-panel"},
	  "acme":   {"category":"vps","kind":"rest","token_env":"ACME_TOKEN"},
	  "broken": ["not","a","dict"]
	}}`
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := CategoryOf("github", f); got != "panel" {
		t.Errorf("user file should override github category: got %q", got)
	}
	if got := CategoryOf("acme", f); got != "vps" {
		t.Errorf("acme category: got %q", got)
	}
	if _, ok := AllSpecs(f)["broken"]; ok {
		t.Error("malformed (non-dict) entry must be skipped")
	}
	// A built-in not mentioned in the user file still resolves.
	if got := CategoryOf("gitlab", f); got != "vcs" {
		t.Errorf("gitlab built-in should survive: got %q", got)
	}
}
