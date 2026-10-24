// Package importer onboards an existing ~/.ssh into the manifest + inventory.
// It parses an ssh config (following relative
// Include directives) into profiles + hosts, fingerprints any private keys it can
// find into the inventory, and adopts non-canonical keys into the profiles/ layout.
// Profile assignment derives from an IdentityFile under profiles/<profile>/ or
// profiles/<category>/<profile>/ (which also carries the category over), else
// "imported".
package importer

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/key"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// kv is one ordered raw_option carried through from the source config.
type kv struct{ Key, Val string }

// ParsedHost is one host block parsed from an ssh config.
type ParsedHost struct {
	Alias        string
	Hostname     string
	User         string
	Port         int
	IdentityFile string // "" if none
	Profile      string
	Category     string // "" unless the IdentityFile sat under profiles/<category>/<profile>/
	Extra        []kv
}

// ImportResult summarizes an import run.
type ImportResult struct {
	Profiles  map[string]int // profile -> host count (counts all parsed hosts)
	KeysFound int
	Adopted   int
	DryRun    bool
}

// Format renders the human-readable import summary (mirrors ImportResult.format).
func (r ImportResult) Format() string {
	head := "import:"
	if r.DryRun {
		head = "import (dry-run):"
	}
	lines := []string{head}
	names := make([]string, 0, len(r.Profiles))
	for p := range r.Profiles {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		lines = append(lines, "  profile "+p+": "+strconv.Itoa(r.Profiles[p])+" host(s)")
	}
	lines = append(lines, "  keys fingerprinted into inventory: "+strconv.Itoa(r.KeysFound))
	if r.Adopted > 0 {
		lines = append(lines, "  keys adopted into profiles/ layout: "+strconv.Itoa(r.Adopted))
	}
	return strings.Join(lines, "\n")
}

var providerByHost = map[string]string{
	"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket",
}

func inferProvider(hostname string) *string {
	if p, ok := providerByHost[strings.ToLower(hostname)]; ok {
		return &p
	}
	return nil
}

// block is one section of an ssh config: a Host line's patterns and the options
// under it, in file order.
type block struct {
	patterns []string // as written, "!" negations included
	all      bool     // the lines before the first Host line: they apply to every host
	opts     []kv
}

// matches reports whether this block applies to alias, as ssh's
// match_pattern_list decides it: some pattern matches and no negated one does.
func (b *block) matches(alias string) bool {
	if b.all {
		return true
	}
	hit := false
	for _, p := range b.patterns {
		if neg := strings.HasPrefix(p, "!"); neg {
			if globMatch(p[1:], alias) {
				return false
			}
		} else if globMatch(p, alias) {
			hit = true
		}
	}
	return hit
}

// names reports whether alias is written literally in this block's Host line,
// which makes it that host's own block rather than one it merely matches.
func (b *block) names(alias string) bool {
	for _, p := range b.patterns {
		if p == alias {
			return true
		}
	}
	return false
}

// parseSSHConfig parses ssh config text into hosts, following relative Include
// files.
//
// It resolves each host the way ssh does rather than block by block: every
// block whose patterns match the alias contributes, in file order, and the
// first value obtained for an option wins. So `Host *` and pattern blocks
// supply what a host leaves unset (before any $USER/22 fallback), a block
// above the host's own beats it, and a repeated alias only fills gaps. Raw
// options are carried only from the block that first names the host - a
// wildcard's options belong in the manifest's global options, not copied
// into every host. Match blocks are never applied: their criteria cannot be
// evaluated at import time.
func parseSSHConfig(text, baseDir string, seen map[string]bool) []*ParsedHost {
	blocks, aliases := collectBlocks(text, baseDir, seen, true)
	hosts := make([]*ParsedHost, 0, len(aliases))
	for _, alias := range aliases {
		hosts = append(hosts, resolveHost(alias, blocks))
	}
	return hosts
}

// collectBlocks splits config text into blocks, inlining Include files in place,
// and lists each literal (non-pattern) alias once, in first-seen order.
func collectBlocks(text, baseDir string, seen map[string]bool, top bool) ([]*block, []string) {
	var blocks []*block
	var aliases []string
	known := map[string]bool{}
	// Options before the first Host line apply to every host - but only in the
	// file ssh reads first. An included file's leading lines inherit the
	// includer's context, which (as before) is treated as no context at all.
	var current *block
	if top {
		current = &block{all: true}
		blocks = append(blocks, current)
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value := splitKV(line)
		switch {
		case keyword == "host":
			current = &block{patterns: argvSplit(value)}
			blocks = append(blocks, current)
			for _, p := range current.patterns {
				if strings.ContainsAny(p, "*?!") || known[p] {
					continue
				}
				known[p] = true
				aliases = append(aliases, p)
			}
		case keyword == "match":
			current = nil
		case keyword == "include" && baseDir != "":
			incBlocks, incAliases := parseIncludes(value, baseDir, seen)
			blocks = append(blocks, incBlocks...)
			for _, a := range incAliases {
				if !known[a] {
					known[a] = true
					aliases = append(aliases, a)
				}
			}
			current = nil
		default:
			if current != nil {
				current.opts = append(current.opts, kv{keyword, value})
			}
		}
	}
	return blocks, aliases
}

// resolveHost applies every block matching alias, in order, first value wins.
func resolveHost(alias string, blocks []*block) *ParsedHost {
	h := &ParsedHost{Alias: alias, Profile: "imported"}
	set := map[string]bool{}
	own := true // the first block naming alias is its own; later ones only fill gaps
	for _, b := range blocks {
		if !b.matches(alias) {
			continue
		}
		carry := own && b.names(alias)
		for _, o := range b.opts {
			applyOption(h, set, o.Key, o.Val, carry)
		}
		if carry {
			own = false
		}
	}
	if !set["port"] {
		h.Port = 22
	}
	if h.IdentityFile != "" {
		h.Profile, h.Category = profileFromIdentity(h.IdentityFile)
	}
	return h
}

// splitKV splits a config line into a lowercased keyword and the trimmed rest.
// The keyword ends at whitespace or '=', and one '=' (with whitespace either
// side) may separate it from the value, as OpenSSH's strdelim allows - so
// `HostName=x`, `HostName = x` and `HostName x` all mean the same thing.
func splitKV(line string) (string, string) {
	i := strings.IndexFunc(line, func(r rune) bool { return r == '=' || unicode.IsSpace(r) })
	if i < 0 {
		return strings.ToLower(line), ""
	}
	rest := strings.TrimLeftFunc(line[i:], unicode.IsSpace)
	rest = strings.TrimPrefix(rest, "=")
	return strings.ToLower(line[:i]), strings.TrimSpace(rest)
}

// applyOption records one option on h unless an earlier one already set it:
// ssh keeps the first value it obtains for each option. carry says whether
// this is the host's own block, the only place raw options are taken from.
func applyOption(h *ParsedHost, set map[string]bool, keyword, value string, carry bool) {
	switch keyword {
	case "hostname", "user", "port", "identityfile":
		if set[keyword] {
			return
		}
		// These take one argument, which ssh unquotes: `IdentityFile "~/my key"`
		// names a path with a space, not one beginning with a quote.
		arg := firstArg(value)
		switch keyword {
		case "hostname":
			h.Hostname = arg
		case "user":
			h.User = arg
		case "port":
			n, err := strconv.Atoi(arg)
			if err != nil {
				return // unusable; leave it unset so a later value can apply
			}
			h.Port = n
		case "identityfile":
			h.IdentityFile = arg
		}
		set[keyword] = true
	default:
		if !carry || manifest.IsDangerousOption(keyword) {
			return // drop command/config-executing directives
		}
		// Carried verbatim, quotes included: it is rendered back into an ssh
		// config, where ssh will unquote it itself.
		h.Extra = append(h.Extra, kv{keyword, value})
	}
}

// firstArg is the first argument of an option value, unquoted.
func firstArg(value string) string {
	if args := argvSplit(value); len(args) > 0 {
		return args[0]
	}
	return ""
}

// argvSplit splits s into arguments as OpenSSH's argv_split does: spaces and
// tabs separate, single or double quotes group (and are removed), and a
// backslash escapes a quote, a backslash, or (outside quotes) a space. Any
// other backslash is literal, which keeps a Windows path like `~\.ssh\id`
// intact. ssh rejects an unterminated quote; here the partial argument is
// kept, since import should salvage what it can rather than fail outright.
func argvSplit(s string) []string {
	var args []string
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		var arg strings.Builder
		var quote byte
		for ; i < len(s); i++ {
			c := s[i]
			if c == '\\' && i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' ||
				(quote == 0 && s[i+1] == ' ')) {
				i++
				arg.WriteByte(s[i])
				continue
			}
			if quote == 0 && (c == ' ' || c == '\t') {
				break // unquoted whitespace ends the argument
			}
			switch {
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
			case quote != 0 && c == quote:
				quote = 0
			default:
				arg.WriteByte(c)
			}
		}
		args = append(args, arg.String())
	}
	return args
}

// globMatch matches s against an ssh pattern, where '*' is any run of
// characters and '?' any one. Case-insensitive, as ssh lowercases the host
// it is matching.
func globMatch(pattern, s string) bool {
	p, t := []rune(strings.ToLower(pattern)), []rune(strings.ToLower(s))
	i, j, star, mark := 0, 0, -1, 0
	for j < len(t) {
		switch {
		case i < len(p) && (p[i] == '?' || p[i] == t[j]):
			i++
			j++
		case i < len(p) && p[i] == '*':
			star, mark = i, j // remember the star; try matching nothing first
			i++
		case star >= 0:
			mark++ // backtrack: let the last star swallow one more character
			i, j = star+1, mark
		default:
			return false
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}

// profileFromIdentity reads the profile (and category, if any) off a key path
// under profiles/: profiles/<profile>/<key> or
// profiles/<category>/<profile>/<key>. A flat profile's rotation archive,
// profiles/<profile>/old/<key>, is three segments deep too and is not a
// category.
func profileFromIdentity(identityFile string) (profile, category string) {
	parts := strings.Split(filepath.ToSlash(identityFile), "/")
	for i, p := range parts {
		if p != "profiles" || i+1 >= len(parts) {
			continue
		}
		rest := parts[i+1:]
		if len(rest) == 3 && rest[1] != "old" {
			return rest[1], rest[0]
		}
		return rest[0], ""
	}
	return "imported", ""
}

// parseIncludes returns the blocks and aliases of every file an Include names,
// in order, so they resolve together with the including file's blocks.
func parseIncludes(pattern, baseDir string, seen map[string]bool) ([]*block, []string) {
	var blocks []*block
	var aliases []string
	for _, token := range strings.Fields(pattern) {
		expanded := expanduser(token)
		full := expanded
		if !filepath.IsAbs(expanded) {
			full = filepath.Join(baseDir, expanded)
		}
		matches, _ := filepath.Glob(full)
		sort.Strings(matches)
		for _, match := range matches {
			abs, err := filepath.Abs(match)
			if err != nil {
				continue
			}
			if resolved, e := filepath.EvalSymlinks(abs); e == nil {
				abs = resolved
			}
			if seen[abs] || !isFile(abs) {
				continue
			}
			seen[abs] = true
			b, err := os.ReadFile(abs)
			if err != nil {
				continue
			}
			bs, as := collectBlocks(string(b), baseDir, seen, false)
			blocks = append(blocks, bs...)
			aliases = append(aliases, as...)
		}
	}
	return blocks, aliases
}

// resolution is how one parsed host maps onto the canonical layout.
type resolution struct {
	keyName   string
	adoptFrom string // source key to copy into profiles/<p>/ ("" if none)
	probe     string // existing key to fingerprint ("" if none)
}

// Importer onboards an ssh config.
type Importer struct {
	p               paths.Paths
	emitUseKeychain bool
	ks              *keystore.KeyStore
}

// New builds an importer.
func New(p paths.Paths, emitUseKeychain bool) *Importer {
	return &Importer{p: p, emitUseKeychain: emitUseKeychain, ks: keystore.New()}
}

// Run parses configPath into a fresh manifest + inventory (replacing any existing).
// With dryRun it parses and reports without writing or adopting keys.
func (im *Importer) Run(configPath string, dryRun bool) (ImportResult, error) {
	configPath = expanduser(configPath)
	if !isFile(configPath) {
		return ImportResult{}, &importError{"no ssh config file to import: " + configPath}
	}
	text, err := os.ReadFile(configPath)
	if err != nil {
		return ImportResult{}, &importError{"cannot read " + configPath + ": " + err.Error()}
	}
	parsed := parseSSHConfig(string(text), filepath.Dir(configPath), map[string]bool{})

	m := manifest.Starter(im.emitUseKeychain) // defaults with the right global options
	order := []string{}
	byProfile := map[string][]manifest.Host{}
	category := map[string]string{} // profile -> the first category its keys were found under
	type rh struct {
		h   *ParsedHost
		res resolution
	}
	var resolved []rh
	seen := map[string]bool{}
	for _, h := range parsed {
		// Keyed on the alias alone, not profile+alias: a repeated alias whose
		// blocks name keys in two profiles is still one ssh host (the first
		// block wins), and the manifest rejects an alias declared twice in any
		// profiles. The parser already yields each alias once; this keeps the
		// manifest valid even if that ever changes.
		if seen[h.Alias] {
			continue
		}
		seen[h.Alias] = true
		res := im.resolveKey(h)
		resolved = append(resolved, rh{h, res})
		kn := res.keyName
		hostName := h.Hostname
		if hostName == "" {
			hostName = h.Alias
		}
		user := h.User
		if user == "" {
			if user = os.Getenv("USER"); user == "" {
				user = "git"
			}
		}
		host := manifest.Host{
			Alias: h.Alias, Hostname: hostName, User: user, Port: h.Port,
			Provider: inferProvider(hostName), KeyName: &kn,
			RawOptions: manifest.NewOrderedOptions(pairs(h.Extra)),
		}
		if _, ok := byProfile[h.Profile]; !ok {
			order = append(order, h.Profile)
		}
		if category[h.Profile] == "" {
			category[h.Profile] = h.Category
		}
		byProfile[h.Profile] = append(byProfile[h.Profile], host)
	}
	for _, name := range order {
		m.SetProfile(name, manifest.Profile{Category: category[name], KeyScope: "per_service", Hosts: byProfile[name]})
	}
	// Save does not validate, and every later command Loads (which does). An
	// import that wrote a manifest Load then rejects would report success and
	// leave sshmgr unusable, so refuse it here - before any key is adopted, and
	// in a dry run too, which should predict the real run.
	if err := m.Validate(); err != nil {
		return ImportResult{}, &importError{"import would produce an invalid manifest: " + err.Error()}
	}

	inv := inventory.New()
	adopted := 0
	for _, r := range resolved {
		ident := m.IdentityFile(r.h.Profile, r.res.keyName)
		if !dryRun && r.res.adoptFrom != "" && im.adoptKey(m, r.res.adoptFrom, r.h.Profile, r.res.keyName) {
			adopted++
		}
		if r.res.probe != "" {
			if fp := im.safeFingerprint(r.res.probe); fp != "" {
				inv.Record(fp, inventory.KeyRecord{
					Profile: r.h.Profile, Path: ident, Type: "ed25519", RotateAfterDays: 365,
				})
			}
		}
	}

	// Counted from what actually reached the manifest, not from what was parsed.
	// Duplicate Host blocks are dropped above (first wins) - appending to an ssh
	// config rather than editing it in place is normal, so a repeated alias is
	// normal - and counting parsed hosts reported an import larger than the one
	// written, with nothing in the summary to say which number was real.
	result := ImportResult{DryRun: dryRun, KeysFound: len(inv.Keys), Adopted: adopted, Profiles: map[string]int{}}
	for name, hosts := range byProfile {
		result.Profiles[name] = len(hosts)
	}
	if !dryRun {
		if err := m.Save(im.p.Manifest()); err != nil {
			return ImportResult{}, err
		}
		if err := inv.Save(im.p.Inventory()); err != nil {
			return ImportResult{}, err
		}
	}
	return result, nil
}

func (im *Importer) resolveKey(h *ParsedHost) resolution {
	if h.IdentityFile == "" {
		kn, _ := key.DeriveKeyName(h.Profile, h.Alias, "ed25519")
		return resolution{keyName: kn}
	}
	real := expanduser(h.IdentityFile)
	pub := real + ".pub"
	probe := ""
	switch {
	case isFile(pub):
		probe = pub
	case exists(real):
		probe = real
	}
	if underProfile(real, h.Profile) {
		return resolution{keyName: filepath.Base(real), probe: probe}
	}
	kn, _ := key.DeriveKeyName(h.Profile, h.Alias, "ed25519")
	adopt := ""
	if exists(real) {
		adopt = real
	}
	return resolution{keyName: kn, adoptFrom: adopt, probe: probe}
}

func underProfile(real, profile string) bool {
	got, _ := profileFromIdentity(real)
	return got == profile && strings.Contains(filepath.ToSlash(real), "/profiles/")
}

// adoptKey copies an existing keypair into the profile's directory
// (profiles/[<category>/]<profile>/<keyName>). Non-destructive: skips if the
// destination already exists.
func (im *Importer) adoptKey(m *manifest.Manifest, srcPriv, profile, keyName string) bool {
	dstPriv := m.KeyPath(im.p.SSHDir, manifest.KeyRef{Profile: profile, KeyName: keyName})
	if exists(dstPriv) || !exists(srcPriv) {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(dstPriv), perms.DirMode); err != nil {
		return false
	}
	_ = perms.SetPerms(filepath.Dir(dstPriv), perms.DirMode)
	if !copyFile(srcPriv, dstPriv) {
		return false
	}
	_ = perms.SetPerms(dstPriv, perms.PrivateKeyMode)
	if exists(srcPriv + ".pub") {
		if copyFile(srcPriv+".pub", dstPriv+".pub") {
			_ = perms.SetPerms(dstPriv+".pub", perms.PublicKeyMode)
		}
	}
	return true
}

func (im *Importer) safeFingerprint(probe string) string {
	fp, err := im.ks.Fingerprint(probe)
	if err != nil {
		return ""
	}
	return fp
}

// --- small helpers ---------------------------------------------------------

type importError struct{ msg string }

func (e *importError) Error() string { return e.msg }

func pairs(extra []kv) [][2]string {
	out := make([][2]string, len(extra))
	for i, e := range extra {
		out[i] = [2]string{e.Key, e.Val}
	}
	return out
}

// expanduser resolves a leading ~ against the user's home directory.
//
// Both separators are accepted. An ssh config written on Windows can say
// `~\.ssh\id_ed25519`, and honouring only "~/" left that as a literal path
// beginning with a tilde - which then failed to glob, so the key was silently
// skipped and the host imported without its identity.
func expanduser(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(p[2:], `\`, "/")))
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func copyFile(src, dst string) bool {
	b, err := os.ReadFile(src)
	if err != nil {
		return false
	}
	return os.WriteFile(dst, b, 0o600) == nil
}
