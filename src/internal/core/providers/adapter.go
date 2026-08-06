package providers

import (
	"encoding/json"
	"path/filepath"
)

// Target is everything a provider needs to act on one host (resolved from the
// manifest). Mirrors providers.base.Target.
type Target struct {
	Alias        string
	Hostname     string
	User         string
	PubkeyPath   string
	PubkeyText   string
	Port         int
	TokenEnv     string // "" == none
	IdentityPath string // private key for verify; "" == none
	KnownHosts   string // per-profile known_hosts; "" == none
}

// SSHDest is user@hostname.
func (t Target) SSHDest() string { return t.User + "@" + t.Hostname }

// DeployOutcome is the result of a deploy attempt. Mirrors base.DeployOutcome.
type DeployOutcome struct {
	Method   string // ssh-copy-id | github-gh | gitlab-glab | <name>-api | manual
	Verified bool   // true == confirmed on the target
	Detail   string
	Error    bool // true == an automated deploy was attempted and FAILED
}

// RemoteKey is one key as listed by a provider's API.
type RemoteKey struct {
	ID, Name, Body string
}

// Provider installs / verifies / revokes a public key on a target. Mirrors the
// providers.base.Provider strategy interface.
type Provider interface {
	Deploy(Target) DeployOutcome
	Verify(Target) bool
	ListDeployed(Target) []string
	Remove(Target) bool
	Rename(Target, string) bool
	ManageURL(Target) string // "" == none
	Name() string
	Category() string
}

// base is the manual / web-panel / unknown-kind provider: it degrades to a manual
// paste step and can't verify or revoke.
type base struct{ spec Spec }

func (b base) Deploy(t Target) DeployOutcome { return manual(b.ManageURL(t), t) }
func (base) Verify(Target) bool              { return false }
func (base) ListDeployed(Target) []string    { return nil }
func (base) Remove(Target) bool              { return false }
func (base) Rename(Target, string) bool      { return false }
func (b base) ManageURL(Target) string       { return b.spec.ResolvedKeysURL() }
func (b base) Name() string                  { return b.spec.Name }
func (b base) Category() string              { return b.spec.Category }

// manual builds the degrade-to-paste outcome. Mirrors Provider._manual.
func manual(manageURL string, t Target) DeployOutcome {
	where := manageURL
	if where == "" {
		where = t.SSHDest() + " (authorized_keys)"
	}
	return DeployOutcome{Method: "manual", Detail: "paste " + filepath.Base(t.PubkeyPath) + " at " + where}
}

// specFor returns the spec for a provider name: the user/embedded catalog entry
// if present, else a built-in. Mirrors registry._spec_for.
func specFor(name, providersFile string) (Spec, bool) {
	if raw, ok := catalogProviders(providersFile)[name]; ok {
		var e catalogEntry
		if json.Unmarshal(raw, &e) == nil {
			return specFromEntry(name, e), true
		}
	}
	s, ok := builtinSpecs[name]
	return s, ok
}

// Resolve resolves a provider name to an adapter instance for its spec. An empty
// or unknown name yields the generic-SSH fallback. Mirrors registry.resolve.
func Resolve(name, providersFile string) Provider {
	if name == "" {
		return GenericSSH{spec: builtinSpecs["generic-ssh"]}
	}
	spec, ok := specFor(name, providersFile)
	if !ok {
		return GenericSSH{spec: builtinSpecs["generic-ssh"]}
	}
	return adapterFor(spec)
}

// adapterFor selects the adapter class for a spec's kind. Mirrors registry._ADAPTERS.
func adapterFor(spec Spec) Provider {
	switch spec.Kind {
	case "github":
		return GitHub{spec: spec}
	case "gitlab":
		return GitLab{spec: spec}
	case "ssh":
		return GenericSSH{spec: spec}
	case "digitalocean":
		return newDigitalOcean(spec)
	case "vultr":
		return newVultr(spec)
	case "hetzner":
		return newHetzner(spec)
	case "linode":
		return newLinode(spec)
	case "scaleway":
		return newScaleway(spec)
	case "rest":
		return newGenericRest(spec)
	default:
		// web-panel, and any unlisted vcs/panel kind -> the universal manual path.
		return base{spec: spec}
	}
}
