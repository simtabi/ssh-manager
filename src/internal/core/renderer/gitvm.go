package renderer

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// SelfPath returns the sshmgr binary a VM host's ProxyCommand runs. A variable so tests pin it.
var SelfPath = defaultSelfPath

// defaultSelfPath prefers the PATH entry (a package manager's stable symlink, such as
// /opt/homebrew/bin/sshmgr) over the resolved executable, whose versioned Cellar path disappears on
// the next upgrade. `doctor` reports a recorded path that has gone; `config render` rewrites it.
func defaultSelfPath() string {
	self, err := os.Executable()
	if err != nil {
		return "sshmgr"
	}
	if onPath, err := exec.LookPath("sshmgr"); err == nil {
		a, errA := os.Stat(onPath)
		b, errB := os.Stat(self)
		if errA == nil && errB == nil && os.SameFile(a, b) {
			return onPath
		}
	}
	return self
}

// ProxyCommandFor is the ProxyCommand a VM host renders: sshmgr asks the hypervisor for the
// VM's current address on each connection.
//
// The path is double-quoted literally, not with Go's %q: ssh does not unescape, so %q would double
// every backslash in a Windows path. A path containing a double quote cannot be quoted for ssh at all
// and falls back to the bare command name, resolved through PATH.
func ProxyCommandFor(alias string) string {
	self := SelfPath()
	if strings.Contains(self, `"`) {
		self = "sshmgr"
	}
	return `"` + self + `" vm proxy ` + alias
}

func proxyFor(h manifest.Host) string {
	if h.VM == nil {
		return ""
	}
	return ProxyCommandFor(h.Alias)
}

// ProxyBinary extracts the binary path from a rendered sshmgr ProxyCommand value, "" for any
// other value. doctor uses it to find a recorded path that no longer exists.
func ProxyBinary(value string) string {
	if !strings.HasPrefix(value, `"`) || !strings.Contains(value, `" vm proxy `) {
		return ""
	}
	return value[1:strings.Index(value, `" vm proxy `)]
}

// gitHubBlock is the `Host github.com` block for ssh mode: plain git@github.com remotes use the
// defaults.git.profile identity. nil when that is not configured.
func gitHubBlock(m *manifest.Manifest) (*RenderHost, error) {
	g := m.Defaults.Git
	if g == nil || g.Profile == "" {
		return nil, nil
	}
	h, ok := manifest.GitHubHostOf(m, g.Profile)
	if !ok {
		return nil, fmt.Errorf("defaults.git.profile %q has no github.com host", g.Profile)
	}
	kname, err := m.ResolvedKeyName(g.Profile, h)
	if err != nil {
		return nil, err
	}
	file, agent := identityFor(m, g.Profile, kname)
	return &RenderHost{
		Alias: "github.com", Hostname: "github.com", User: "git", Port: h.Port,
		IdentityFile: file, IdentityAgent: agent, KnownHosts: m.KnownHostsFile(),
		RawOptions: h.RawOptions,
	}, nil
}

func gitBanner(profile string) string {
	prefix := "# --- git ssh mode: github.com as " + profile + " "
	if len(prefix) >= bannerWidth {
		return prefix
	}
	return prefix + strings.Repeat("-", bannerWidth-len(prefix))
}
