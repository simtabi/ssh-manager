package manifest

import (
	"fmt"
	"sort"
	"strings"
)

// Git remote modes. A checkout's origin points at GitHub one of three ways:
// through a profile's own SSH alias (git@github-<profile>:owner/repo.git), through
// plain SSH to github.com (the key bound to the rendered `Host github.com`), or over
// HTTPS (the gh-app credential helper).
const (
	GitModeProfile = "profile"
	GitModeSSH     = "ssh"
	GitModeHTTPS   = "https"
)

// GitModes lists the modes in the order they are documented.
var GitModes = []string{GitModeProfile, GitModeSSH, GitModeHTTPS}

// GitDefaults configures `sshmgr git`. Absent, the mode is profile and no
// `Host github.com` block is rendered, so a manifest without it renders as before.
type GitDefaults struct {
	// Mode is the default remote mode; empty means profile.
	Mode string `json:"mode,omitempty"`
	// Profile is the default identity: its GitHub key is bound to `Host github.com`
	// (ssh mode), and it is used for an owner Orgs does not list.
	Profile string `json:"profile,omitempty"`
	// Orgs maps a GitHub owner to the profile whose key it uses.
	Orgs map[string]string `json:"orgs,omitempty"`
}

// EffectiveMode is Mode, or profile when unset.
func (g *GitDefaults) EffectiveMode() string {
	if g == nil || g.Mode == "" {
		return GitModeProfile
	}
	return g.Mode
}

// Hypervisors sshmgr can resolve a devbox's address through.
const (
	HypervisorParallels = "parallels"
	HypervisorVMPal     = "vmpal"
	HypervisorVMware    = "vmware"
	HypervisorUTM       = "utm"
	HypervisorLima      = "lima"
	HypervisorOrbStack  = "orbstack"
	HypervisorPodman    = "podman"
)

// Hypervisors lists the supported hypervisors.
var Hypervisors = []string{HypervisorParallels, HypervisorVMPal, HypervisorVMware,
	HypervisorUTM, HypervisorLima, HypervisorOrbStack, HypervisorPodman}

// VMSpec marks a host as a local VM: its address comes from the hypervisor at
// connect time (`sshmgr vm proxy`), because a VM's IP changes and a static
// HostName goes stale.
type VMSpec struct {
	Hypervisor string `json:"hypervisor"`
	Name       string `json:"name"`
}

// GitHubHostOf returns the profile's GitHub host: the first one whose hostname is
// github.com. A profile with none has no profile-mode alias.
func GitHubHostOf(m *Manifest, profile string) (Host, bool) {
	p, ok := m.Profiles[profile]
	if !ok {
		return Host{}, false
	}
	for _, h := range p.Hosts {
		if strings.EqualFold(h.Hostname, "github.com") {
			return h, true
		}
	}
	return Host{}, false
}

// ProfileForOwner picks the profile a GitHub owner uses: Orgs, then Profile, then
// the only profile with a GitHub host. It fails rather than guess between several.
func ProfileForOwner(m *Manifest, owner string) (string, error) {
	g := m.Defaults.Git
	if g != nil {
		for org, prof := range g.Orgs {
			if strings.EqualFold(org, owner) {
				return prof, nil
			}
		}
		if g.Profile != "" {
			return g.Profile, nil
		}
	}
	var with []string
	for _, name := range m.ProfileNames() {
		if _, ok := GitHubHostOf(m, name); ok {
			with = append(with, name)
		}
	}
	switch len(with) {
	case 1:
		return with[0], nil
	case 0:
		return "", fmt.Errorf("no profile has a github.com host")
	}
	sort.Strings(with)
	return "", fmt.Errorf("owner %q: several profiles have a GitHub host (%s); set defaults.git.orgs or --profile",
		owner, strings.Join(with, ", "))
}

func validMode(mode string) bool {
	for _, m := range GitModes {
		if m == mode {
			return true
		}
	}
	return false
}

func checkGit(m *Manifest) error {
	g := m.Defaults.Git
	if g == nil {
		return nil
	}
	if g.Mode != "" && !validMode(g.Mode) {
		return fmt.Errorf("defaults.git.mode %q is not one of %s", g.Mode, strings.Join(GitModes, ", "))
	}
	needsGitHub := func(field, prof string) error {
		if _, ok := m.Profiles[prof]; !ok {
			return fmt.Errorf("%s: profile %q does not exist", field, prof)
		}
		if _, ok := GitHubHostOf(m, prof); !ok {
			return fmt.Errorf("%s: profile %q has no github.com host", field, prof)
		}
		return nil
	}
	if g.Profile != "" {
		if err := needsGitHub("defaults.git.profile", g.Profile); err != nil {
			return err
		}
		// `Host github.com` is rendered from it; an alias of that name would shadow it.
		for name, p := range m.Profiles {
			for _, h := range p.Hosts {
				if strings.EqualFold(h.Alias, "github.com") {
					return fmt.Errorf("profile %s: alias github.com clashes with the Host github.com block defaults.git.profile renders", name)
				}
			}
		}
	}
	if g.Mode == GitModeSSH && g.Profile == "" {
		return fmt.Errorf("defaults.git.mode ssh needs defaults.git.profile: its key is bound to Host github.com")
	}
	for org, prof := range g.Orgs {
		if err := safeSegment("defaults.git.orgs owner", org); err != nil {
			return err
		}
		if err := needsGitHub("defaults.git.orgs."+org, prof); err != nil {
			return err
		}
	}
	return nil
}

func checkVM(profile string, h Host) error {
	if h.VM == nil {
		return nil
	}
	known := false
	for _, hv := range Hypervisors {
		if hv == h.VM.Hypervisor {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%s/%s: vm.hypervisor %q is not one of %s", profile, h.Alias, h.VM.Hypervisor, strings.Join(Hypervisors, ", "))
	}
	if strings.TrimSpace(h.VM.Name) == "" {
		return fmt.Errorf("%s/%s: vm.name is empty", profile, h.Alias)
	}
	// Names like "Ubuntu 24.04" carry spaces. The name only ever reaches the hypervisor CLI as one
	// argv element, never a shell, and the rendered ProxyCommand names the alias, not the VM.
	return rejectControl("vm.name", h.VM.Name)
}
