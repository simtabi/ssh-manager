// Package renderer renders the managed SSH config, ported from
// src/ssh_manager/core/renderer.py (+ its two Jinja2 templates). One renderer
// backs config render, config check, and reconcile so they cannot disagree.
package renderer

import (
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

const (
	// ManagedHeader/ManagedEnd delimit the block ssh-manager owns in ~/.ssh/config.
	ManagedHeader = "# Managed by ssh-manager - do not edit (run: sshmgr config render)"
	ManagedEnd    = "# End of ssh-manager-managed block - content outside it is preserved"
	// RootConfig is the top-level config file's relative path under ~/.ssh.
	RootConfig = "config"
)

// Pre-rename markers, still recognized so a config written by the old "sshmgr"
// name is cleanly re-owned (not duplicated) on the next render.
var legacyHeaders = []string{"# Managed by sshmgr - do not edit (run: sshmgr config render)"}
var legacyEnds = []string{"# End of sshmgr-managed block - content outside it is preserved"}

func isManagedHeader(s string) bool { return s == ManagedHeader || contains(legacyHeaders, s) }
func isManagedEnd(s string) bool    { return s == ManagedEnd || contains(legacyEnds, s) }

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// RenderHost is the flat view a profile-config block needs for one host.
type RenderHost struct {
	Alias        string
	Hostname     string
	User         string
	Port         int
	IdentityFile string
	KnownHosts   string
	RawOptions   manifest.OrderedOptions
}

// RenderRootConfig renders the top-level managed block. UseKeychain is dropped
// unless emitUseKeychain (macOS only).
func RenderRootConfig(globalOptions manifest.OrderedOptions, emitUseKeychain bool) string {
	var b strings.Builder
	b.WriteString(ManagedHeader + "\n")
	b.WriteString("Include profiles/*/config\n\n")
	b.WriteString("Host *\n")
	for _, k := range globalOptions.Keys() {
		if k == "UseKeychain" && !emitUseKeychain {
			continue
		}
		b.WriteString("    " + k + " " + globalOptions.Get(k) + "\n")
	}
	b.WriteString(ManagedEnd + "\n")
	return b.String()
}

// RenderProfileConfig renders one profiles/<name>/config from its hosts.
func RenderProfileConfig(hosts []RenderHost) string {
	var b strings.Builder
	b.WriteString(ManagedHeader + "\n")
	for _, h := range hosts {
		b.WriteString("Host " + h.Alias + "\n")
		b.WriteString("    HostName " + h.Hostname + "\n")
		b.WriteString("    User " + h.User + "\n")
		if h.Port != 0 && h.Port != 22 {
			b.WriteString("    Port " + strconv.Itoa(h.Port) + "\n")
		}
		b.WriteString("    IdentityFile " + h.IdentityFile + "\n")
		b.WriteString("    UserKnownHostsFile " + h.KnownHosts + "\n")
		for _, k := range h.RawOptions.Keys() {
			b.WriteString("    " + k + " " + h.RawOptions.Get(k) + "\n")
		}
		b.WriteString("\n") // blank line between/after host blocks (template)
	}
	return b.String()
}

// ComposeRootConfig returns the full ~/.ssh/config with the managed block in
// place, preserving foreign content above and below it (e.g. an OrbStack
// Include). Old/legacy markers are recognized so the block is re-owned, not
// duplicated. An empty existing returns the managed block as-is.
func ComposeRootConfig(existing, managed string) string {
	if existing == "" {
		return managed
	}
	lines := splitLines(existing)
	start := -1
	for i, ln := range lines {
		if isManagedHeader(strings.TrimSpace(ln)) {
			start = i
			break
		}
	}
	var preamble, trailer []string
	if start == -1 {
		preamble = lines
	} else {
		preamble = lines[:start]
		end := -1
		for i := start + 1; i < len(lines); i++ {
			if isManagedEnd(strings.TrimSpace(lines[i])) {
				end = i
				break
			}
		}
		if end != -1 {
			trailer = lines[end+1:]
		}
	}
	pre := strings.TrimRight(strings.Join(preamble, "\n"), "\n")
	trail := strings.Trim(strings.Join(trailer, "\n"), "\n")
	block := managed
	if !strings.HasSuffix(block, "\n") {
		block += "\n"
	}
	out := ""
	if pre != "" {
		out = pre + "\n\n"
	}
	out += block
	if trail != "" {
		out += "\n" + trail + "\n"
	}
	return out
}

// RenderAll renders every managed file: {relative path -> content}. Keys are
// "config" and "profiles/<p>/config". Empty profiles render no file.
func RenderAll(m *manifest.Manifest, emitUseKeychain bool) (map[string]string, error) {
	out := map[string]string{
		RootConfig: RenderRootConfig(m.Defaults.GlobalOptions, emitUseKeychain),
	}
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	byProfile := map[string][]RenderHost{}
	for _, rk := range resolved {
		byProfile[rk.Profile] = append(byProfile[rk.Profile], RenderHost{
			Alias:        rk.Host.Alias,
			Hostname:     rk.Host.Hostname,
			User:         rk.Host.User,
			Port:         rk.Host.Port,
			IdentityFile: rk.IdentityFile,
			KnownHosts:   m.KnownHostsFile(rk.Profile),
			RawOptions:   rk.Host.RawOptions,
		})
	}
	for pname, hosts := range byProfile {
		out["profiles/"+pname+"/config"] = RenderProfileConfig(hosts)
	}
	return out, nil
}

func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}
