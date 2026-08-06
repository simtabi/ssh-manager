// Package renderer renders the managed SSH config, ported from
// src/ssh_manager/core/renderer.py (+ its two Jinja2 templates). One renderer
// backs config render, config check, and reconcile so they cannot disagree.
package renderer

import (
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

const (
	// ManagedHeader/ManagedEnd delimit the block ssh-manager owns in ~/.ssh/config.
	ManagedHeader = "# Managed by ssh-manager - do not edit (run: sshmgr config render)"
	ManagedEnd    = "# End of ssh-manager-managed block - content outside it is preserved"
	// RootConfig is the top-level config file's relative path under ~/.ssh.
	// It is the only file the renderer produces: every Host block lives inline
	// here rather than in a per-profile file pulled in via Include.
	RootConfig = "config"
	// bannerWidth is the total column width of a "# --- profile: <name> ---"
	// banner line, dashes padding out the remainder.
	bannerWidth = 69
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

// RenderHost is the flat view a host block needs to render.
type RenderHost struct {
	Alias        string
	Hostname     string
	User         string
	Port         int
	IdentityFile string
	KnownHosts   string
	RawOptions   manifest.OrderedOptions
}

const identitiesOnlyKey = "IdentitiesOnly"

// identitiesOnly is the value to bind a host to its own key. Every host block
// carries this directive: without it ssh offers each identity loaded in the agent
// to the server in turn, disclosing the whole key inventory to any host reached.
// Relying on defaults.global_options for it, as the config used to, meant editing
// that map silently switched the protection off. An explicit per-host value is
// still honoured, so the directive is pinned in place rather than forced.
func identitiesOnly(opts manifest.OrderedOptions) string {
	for _, k := range opts.Keys() {
		if strings.EqualFold(k, identitiesOnlyKey) {
			return opts.Get(k)
		}
	}
	return "yes"
}

const hashKnownHostsKey = "HashKnownHosts"

// hashKnownHosts is the value for hashing host names ssh pins by itself.
//
// sshmgr hashes the names it writes, but ssh appends its own entry whenever the
// user accepts an unknown host at the prompt, and it writes plaintext unless told
// otherwise. Without this the trust store drifts back to a readable inventory one
// accepted host at a time. An explicit value in global_options wins, so this is a
// default rather than an override.
func hashKnownHosts(opts manifest.OrderedOptions) string {
	for _, k := range opts.Keys() {
		if strings.EqualFold(k, hashKnownHostsKey) {
			return opts.Get(k)
		}
	}
	return "yes"
}

// profileBanner marks where one profile's host blocks begin in the flat file,
// so a reader (or `sshmgr show`) can scan the single config the way separate
// per-profile files used to make obvious.
func profileBanner(name string) string {
	prefix := "# --- profile: " + name + " "
	if len(prefix) >= bannerWidth {
		return prefix
	}
	return prefix + strings.Repeat("-", bannerWidth-len(prefix))
}

func writeHostBlock(b *strings.Builder, h RenderHost) {
	b.WriteString("Host " + h.Alias + "\n")
	b.WriteString("    HostName " + h.Hostname + "\n")
	b.WriteString("    User " + h.User + "\n")
	if h.Port != 0 && h.Port != 22 {
		b.WriteString("    Port " + strconv.Itoa(h.Port) + "\n")
	}
	b.WriteString("    IdentityFile " + h.IdentityFile + "\n")
	b.WriteString("    IdentitiesOnly " + identitiesOnly(h.RawOptions) + "\n")
	b.WriteString("    UserKnownHostsFile " + h.KnownHosts + "\n")
	for _, k := range h.RawOptions.Keys() {
		if strings.EqualFold(k, identitiesOnlyKey) {
			continue // already emitted next to the IdentityFile it constrains
		}
		b.WriteString("    " + k + " " + h.RawOptions.Get(k) + "\n")
	}
	b.WriteString("\n") // blank line between/after host blocks
}

func writeGlobalBlock(b *strings.Builder, globalOptions manifest.OrderedOptions, emitUseKeychain bool) {
	b.WriteString("Host *\n")
	for _, k := range globalOptions.Keys() {
		if k == "UseKeychain" && !emitUseKeychain {
			continue
		}
		if strings.EqualFold(k, hashKnownHostsKey) {
			continue // emitted below regardless, so it is never dropped by omission
		}
		b.WriteString("    " + k + " " + globalOptions.Get(k) + "\n")
	}
	b.WriteString("    HashKnownHosts " + hashKnownHosts(globalOptions) + "\n")
}

// RenderRootConfig renders the entire managed block: every profile's hosts
// inline under a banner (in manifest/file order), then the global Host * block
// last.
//
// Host * must stay last. OpenSSH takes the first value it obtains for a given
// keyword, so a global block placed above the per-host blocks would silently
// override their more specific directives. That ordering used to be incidental
// - Include sat above Host * and the included files expanded in place - inline
// rendering makes it explicit and load-bearing.
func RenderRootConfig(m *manifest.Manifest, emitUseKeychain bool) (string, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return "", err
	}
	byProfile := map[string][]RenderHost{}
	for _, rk := range resolved {
		byProfile[rk.Profile] = append(byProfile[rk.Profile], RenderHost{
			Alias:        rk.Host.Alias,
			Hostname:     rk.Host.Hostname,
			User:         rk.Host.User,
			Port:         rk.Host.Port,
			IdentityFile: rk.IdentityFile,
			KnownHosts:   m.KnownHostsFile(),
			RawOptions:   rk.Host.RawOptions,
		})
	}
	var b strings.Builder
	b.WriteString(ManagedHeader + "\n\n")
	for _, pname := range m.ProfileNames() {
		hosts := byProfile[pname]
		if len(hosts) == 0 {
			continue
		}
		b.WriteString(profileBanner(pname) + "\n")
		for _, h := range hosts {
			writeHostBlock(&b, h)
		}
	}
	writeGlobalBlock(&b, m.Defaults.GlobalOptions, emitUseKeychain)
	b.WriteString(ManagedEnd + "\n")
	return b.String(), nil
}

// RenderHostBlockFor renders the Host block one manifest host produces - byte
// for byte what RenderRootConfig emits for it. `sshmgr show` uses it to answer
// "what does this alias actually do" from the manifest, without asking the user
// to find the block in a file that now holds every profile's hosts at once.
func RenderHostBlockFor(m *manifest.Manifest, profile string, host manifest.Host) (string, error) {
	kname, err := m.ResolvedKeyName(profile, host)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	writeHostBlock(&b, RenderHost{
		Alias:        host.Alias,
		Hostname:     host.Hostname,
		User:         host.User,
		Port:         host.Port,
		IdentityFile: m.IdentityFile(profile, kname),
		KnownHosts:   m.KnownHostsFile(),
		RawOptions:   host.RawOptions,
	})
	return b.String(), nil
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

// RenderAll renders every managed file: {relative path -> content}. There is
// exactly one entry ("config"); the map return type is kept so configsvc's
// diff/prune machinery does not need to special-case a single file.
func RenderAll(m *manifest.Manifest, emitUseKeychain bool) (map[string]string, error) {
	root, err := RenderRootConfig(m, emitUseKeychain)
	if err != nil {
		return nil, err
	}
	return map[string]string{RootConfig: root}, nil
}

func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}
