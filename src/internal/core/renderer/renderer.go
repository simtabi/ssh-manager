// Package renderer renders the managed SSH config, ported from
// one template pair. One renderer
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
	// Every uncategorized profile's Host blocks live inline here. A profile
	// with a category renders into profiles/<category>/config instead, which
	// the root config Includes - one file per category, never one per profile.
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
	// IdentityAgent is the agent socket for a key kept in 1Password, "" for a
	// key on disk. Rendered quoted: the macOS socket path contains a space.
	IdentityAgent string
	KnownHosts    string
	RawOptions    manifest.OrderedOptions
	// ProxyCommand is set by sshmgr for a VM host (never from raw_options, which may not hold one).
	ProxyCommand string
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
	portWritten := h.Port != 0 && h.Port != 22
	if portWritten {
		b.WriteString("    Port " + strconv.Itoa(h.Port) + "\n")
	}
	b.WriteString("    IdentityFile " + h.IdentityFile + "\n")
	if h.IdentityAgent != "" && !hasOption(h.RawOptions, "IdentityAgent") {
		b.WriteString("    IdentityAgent \"" + h.IdentityAgent + "\"\n")
	}
	b.WriteString("    IdentitiesOnly " + identitiesOnly(h.RawOptions) + "\n")
	b.WriteString("    UserKnownHostsFile " + h.KnownHosts + "\n")
	if h.ProxyCommand != "" {
		b.WriteString("    ProxyCommand " + h.ProxyCommand + "\n")
	}
	for _, k := range h.RawOptions.Keys() {
		if strings.EqualFold(k, identitiesOnlyKey) {
			continue // already emitted next to the IdentityFile it constrains
		}
		// A keyword a managed line above already set would never be read: ssh
		// keeps the first value (and IdentityFile would add a second key). It is
		// left out so the block shows the one value ssh uses; doctor reports it.
		// The one exception is Port at its default, where no managed line is
		// written and the raw value is the only one - and always has applied.
		if _, managed := manifest.ManagedHostOption(k); managed &&
			(portWritten || !strings.EqualFold(k, "Port")) {
			continue
		}
		b.WriteString("    " + k + " " + h.RawOptions.Get(k) + "\n")
	}
	b.WriteString("\n") // blank line between/after host blocks
}

// hasOption reports whether the host sets key itself; an explicit value wins.
func hasOption(opts manifest.OrderedOptions, key string) bool {
	for _, k := range opts.Keys() {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// identityFor is what a host block points ssh at: the private key on disk, or
// for a 1Password profile the public key plus the 1Password agent, which is
// how ssh picks one key out of an agent.
func identityFor(m *manifest.Manifest, profile, keyName string) (file, agent string) {
	file = m.IdentityFile(profile, keyName)
	if m.Profiles[profile].InOnePassword() {
		file += ".pub"
		agent = m.Defaults.OnePasswordAgentSocket()
	}
	return file, agent
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

// RenderRootConfig renders the entire managed block: one Include per category
// in use, then every uncategorized profile's hosts inline under a banner (in
// manifest/file order), then the global Host * block last.
//
// Host * must stay last. OpenSSH takes the first value it obtains for a given
// keyword, so a global block placed above the per-host blocks would silently
// override their more specific directives. The category Includes therefore sit
// at the top of the block, where each included file expands in place ahead of
// Host *.
//
// The Includes open with `Match all`. An Include that follows a Host or Match
// line is conditional on it, and the managed block is composed under whatever
// foreign content the user keeps above it - a hand-written Host block there
// would otherwise scope every category to that one host and leave the rest
// unconfigured, with no error. `Match all` resets the condition to every host.
// It is emitted only when there is a category to include, so a manifest with
// none renders byte-identical to before.
func RenderRootConfig(m *manifest.Manifest, emitUseKeychain bool) (string, error) {
	byProfile, err := hostsByProfile(m)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(ManagedHeader + "\n\n")
	if cats := m.Categories(); len(cats) > 0 {
		b.WriteString("Match all\n")
		for _, c := range cats {
			b.WriteString("Include " + manifest.CategoryConfigFile(c) + "\n")
		}
		b.WriteString("\n")
	}
	for _, pname := range m.ProfileNames() {
		if m.Profiles[pname].Category != "" {
			continue // rendered into its category's file
		}
		writeProfile(&b, pname, byProfile[pname])
	}
	// Host github.com sits after every profile block and before Host *, the only other block that
	// could match it.
	gh, err := gitHubBlock(m)
	if err != nil {
		return "", err
	}
	if gh != nil {
		b.WriteString(gitBanner(m.Defaults.Git.Profile) + "\n")
		writeHostBlock(&b, *gh)
	}
	writeGlobalBlock(&b, m.Defaults.GlobalOptions, emitUseKeychain)
	b.WriteString(ManagedEnd + "\n")
	return b.String(), nil
}

// RenderCategoryConfig renders profiles/<category>/config: the Host blocks of
// every profile in that category, in manifest (file) order. It carries the
// managed header so sshmgr can tell a file it wrote from one a user wrote
// there by hand, and no Host * block - the root config's applies to every
// host, wherever its block lives.
func RenderCategoryConfig(m *manifest.Manifest, category string) (string, error) {
	byProfile, err := hostsByProfile(m)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(ManagedHeader + "\n")
	b.WriteString("# Category: " + category + " - included from ~/.ssh/config\n\n")
	for _, pname := range m.ProfileNames() {
		if m.Profiles[pname].Category == category {
			writeProfile(&b, pname, byProfile[pname])
		}
	}
	return b.String(), nil
}

func hostsByProfile(m *manifest.Manifest) (map[string][]RenderHost, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	byProfile := map[string][]RenderHost{}
	for _, rk := range resolved {
		file, agent := identityFor(m, rk.Profile, rk.KeyName)
		byProfile[rk.Profile] = append(byProfile[rk.Profile], RenderHost{
			Alias:         rk.Host.Alias,
			Hostname:      rk.Host.Hostname,
			User:          rk.Host.User,
			Port:          rk.Host.Port,
			IdentityFile:  file,
			IdentityAgent: agent,
			KnownHosts:    m.KnownHostsFile(),
			RawOptions:    rk.Host.RawOptions,
			ProxyCommand:  proxyFor(rk.Host),
		})
	}
	return byProfile, nil
}

func writeProfile(b *strings.Builder, pname string, hosts []RenderHost) {
	if len(hosts) == 0 {
		return
	}
	b.WriteString(profileBanner(pname) + "\n")
	for _, h := range hosts {
		writeHostBlock(b, h)
	}
}

// IsManagedFile reports whether content opens with the managed header (or the
// pre-rename one) - i.e. whether sshmgr wrote it.
func IsManagedFile(content string) bool {
	first, _, _ := strings.Cut(content, "\n")
	return isManagedHeader(strings.TrimSpace(first))
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
	file, agent := identityFor(m, profile, kname)
	var b strings.Builder
	writeHostBlock(&b, RenderHost{
		Alias:         host.Alias,
		Hostname:      host.Hostname,
		User:          host.User,
		Port:          host.Port,
		IdentityFile:  file,
		IdentityAgent: agent,
		KnownHosts:    m.KnownHostsFile(),
		RawOptions:    host.RawOptions,
		ProxyCommand:  proxyFor(host),
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

// RenderAll renders every managed file: {relative path -> content} - the root
// config, plus profiles/<category>/config for each category in use.
func RenderAll(m *manifest.Manifest, emitUseKeychain bool) (map[string]string, error) {
	root, err := RenderRootConfig(m, emitUseKeychain)
	if err != nil {
		return nil, err
	}
	out := map[string]string{RootConfig: root}
	for _, c := range m.Categories() {
		content, err := RenderCategoryConfig(m, c)
		if err != nil {
			return nil, err
		}
		out[manifest.CategoryConfigRel(c)] = content
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
