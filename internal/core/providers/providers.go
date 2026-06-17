// Package providers is the read-only provider catalog, ported from the spec/
// registry parts of src/ssh_manager/providers (base.py + registry.py). It resolves
// a provider name to a ProviderSpec - category, host, keys URL, CLI, token env -
// which powers list/view/audit labels and `list --type`. The deploy/credential
// adapter behavior is not ported here (that lands in a later wave); this is the
// catalog only.
package providers

import (
	_ "embed"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// defaultCatalog is the catalog shipped with the package, kept byte-identical to
// the repo config/providers.json (a test enforces it), mirroring Python's
// ssh_manager/data/providers.json. Used when the user has no providers.json.
//
//go:embed default_providers.json
var defaultCatalog []byte

// Spec is one provider instance: a service (cloud or self-hosted) a public key can
// be deployed to. Mirrors providers.base.ProviderSpec.
type Spec struct {
	Name     string
	Kind     string // github | gitlab | gitea | web-panel | ssh | rest | ...
	Category string // vcs | panel | server | vps | generic
	Host     string
	APIBase  string
	KeysURL  string // explicit override; else derived from kind+host
	CLI      string // gh | glab
	TokenEnv string
	Rest     map[string]any // generic REST config (kind 'rest')
}

// ResolvedKeysURL is the best-effort "add an SSH key" page (explicit, else derived).
func (s Spec) ResolvedKeysURL() string {
	if s.KeysURL != "" {
		return s.KeysURL
	}
	return keysURLFor(s.Kind, s.Host)
}

// builtinSpecs are sensible defaults so the tool works before any providers.json
// is consulted. Mirrors registry._BUILTIN_SPECS.
var builtinSpecs = map[string]Spec{
	"github":       {Name: "github", Kind: "github", Category: "vcs", Host: "github.com", CLI: "gh", TokenEnv: "GH_TOKEN"},
	"gitlab":       {Name: "gitlab", Kind: "gitlab", Category: "vcs", Host: "gitlab.com", CLI: "glab", TokenEnv: "GLAB_TOKEN"},
	"ploi":         {Name: "ploi", Kind: "web-panel", Category: "panel", KeysURL: "https://ploi.io/servers"},
	"generic-ssh":  {Name: "generic-ssh", Kind: "ssh", Category: "server"},
	"digitalocean": {Name: "digitalocean", Kind: "digitalocean", Category: "vps", TokenEnv: "DIGITALOCEAN_TOKEN"},
	"vultr":        {Name: "vultr", Kind: "vultr", Category: "vps", TokenEnv: "VULTR_API_KEY"},
	"hetzner":      {Name: "hetzner", Kind: "hetzner", Category: "vps", TokenEnv: "HCLOUD_TOKEN"},
	"linode":       {Name: "linode", Kind: "linode", Category: "vps", TokenEnv: "LINODE_TOKEN"},
	"scaleway":     {Name: "scaleway", Kind: "scaleway", Category: "vps", TokenEnv: "SCW_SECRET_KEY"},
}

// catalogEntry is one providers.json entry. Unknown keys are ignored (a hand-edited
// file may carry extras like "method"), matching the Python .get()-based parse.
type catalogEntry struct {
	Kind      string         `json:"kind"`
	Category  string         `json:"category"`
	Host      string         `json:"host"`
	API       string         `json:"api"`
	KeysURL   string         `json:"keys_url"`
	ManageURL string         `json:"manage_url"`
	CLI       string         `json:"cli"`
	TokenEnv  string         `json:"token_env"`
	Rest      map[string]any `json:"rest"`
}

func specFromEntry(name string, e catalogEntry) Spec {
	kind := e.Kind
	if kind == "" {
		kind = "generic"
	}
	cat := e.Category
	if cat == "" {
		cat = "generic"
	}
	keysURL := e.KeysURL
	if keysURL == "" {
		keysURL = e.ManageURL
	}
	return Spec{
		Name: name, Kind: kind, Category: cat, Host: e.Host, APIBase: e.API,
		KeysURL: keysURL, CLI: e.CLI, TokenEnv: e.TokenEnv, Rest: e.Rest,
	}
}

// catalogProviders returns the "providers" map from the effective catalog: the
// user's providersFile if it exists, else the embedded default. Tolerates a file
// that is valid JSON but the wrong shape (returns no providers).
func catalogProviders(providersFile string) map[string]json.RawMessage {
	raw := defaultCatalog
	if providersFile != "" {
		if b, err := os.ReadFile(providersFile); err == nil {
			raw = b
		}
	}
	var top struct {
		Providers map[string]json.RawMessage `json:"providers"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil
	}
	return top.Providers
}

// AllSpecs returns every known provider spec by name: built-ins, then the catalog
// (user file else embedded default) overriding. Mirrors registry.all_specs.
func AllSpecs(providersFile string) map[string]Spec {
	specs := make(map[string]Spec, len(builtinSpecs))
	for k, v := range builtinSpecs {
		specs[k] = v
	}
	for name, raw := range catalogProviders(providersFile) {
		var e catalogEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue // non-dict entry -> skip, as the Python isinstance check does
		}
		specs[name] = specFromEntry(name, e)
	}
	return specs
}

// Info is a configured provider and whether its credential is present right now.
// Mirrors facade.ProviderInfo.
type Info struct {
	Name         string
	Kind         string
	Category     string
	TokenEnv     string
	TokenPresent bool
}

// List returns every configured provider, sorted by name, with live credential
// presence resolved via getenv (pass os.Getenv). Mirrors facade.list_providers.
func List(providersFile string, getenv func(string) string) []Info {
	specs := AllSpecs(providersFile)
	names := make([]string, 0, len(specs))
	for n := range specs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Info, 0, len(names))
	for _, n := range names {
		s := specs[n]
		present := s.TokenEnv != "" && getenv(s.TokenEnv) != ""
		out = append(out, Info{Name: n, Kind: s.Kind, Category: s.Category, TokenEnv: s.TokenEnv, TokenPresent: present})
	}
	return out
}

// DefaultCatalog returns the embedded shipped catalog bytes (for `providers --export`).
func DefaultCatalog() []byte { return defaultCatalog }

// CategoryOf maps a provider name to its category. An empty or unknown name falls
// back to "server" - the generic-SSH category, matching registry.resolve().
func CategoryOf(name, providersFile string) string {
	if name != "" {
		if s, ok := AllSpecs(providersFile)[name]; ok {
			return s.Category
		}
	}
	return "server"
}

var defaultHost = map[string]string{
	"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org",
	"gitea": "gitea.com", "codeberg": "codeberg.org", "sourcehut": "meta.sr.ht",
}

var keysURLTemplate = map[string]string{
	"github":           "https://{host}/settings/keys",
	"gitlab":           "https://{host}/-/user_settings/ssh_keys",
	"gitea":            "https://{host}/user/settings/keys",
	"codeberg":         "https://{host}/user/settings/keys",
	"forgejo":          "https://{host}/user/settings/keys",
	"gogs":             "https://{host}/user/settings/ssh",
	"bitbucket":        "https://{host}/account/settings/ssh-keys/",
	"bitbucket-server": "https://{host}/plugins/servlet/ssh/account/keys",
	"sourcehut":        "https://{host}/keys",
	"azure-devops":     "https://{host}/_usersSettings/keys",
	"aws-codecommit":   "https://console.aws.amazon.com/iam/home#/security_credentials",
}

// keysURLFor derives the "add an SSH key" page for a VCS instance. Mirrors
// providers.base.keys_url_for.
func keysURLFor(kind, host string) string {
	tmpl, hasTmpl := keysURLTemplate[kind]
	if hasTmpl && !strings.Contains(tmpl, "{host}") {
		return tmpl // host-independent (e.g. aws-codecommit)
	}
	h := host
	if h == "" {
		h = defaultHost[kind]
	}
	if h == "" {
		return ""
	}
	if hasTmpl {
		return strings.ReplaceAll(tmpl, "{host}", h)
	}
	return "https://" + h
}
