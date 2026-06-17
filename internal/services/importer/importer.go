// Package importer onboards an existing ~/.ssh into the manifest + inventory,
// ported from services/importer.py. It parses an ssh config (following relative
// Include directives) into profiles + hosts, fingerprints any private keys it can
// find into the inventory, and adopts non-canonical keys into the profiles/ layout.
// Profile assignment derives from an IdentityFile under profiles/<profile>/, else
// "imported".
package importer

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/key"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
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

var simpleKeys = map[string]bool{"hostname": true, "user": true, "port": true, "identityfile": true}

// parseSSHConfig parses ssh config text into hosts, following relative Include
// files. Wildcard/global Host blocks are skipped; Match ends the current block.
func parseSSHConfig(text, baseDir string, seen map[string]bool) []*ParsedHost {
	var hosts, current []*ParsedHost
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value := splitKV(line)
		switch {
		case keyword == "host":
			current = nil
			for _, alias := range strings.Fields(value) {
				if strings.ContainsAny(alias, "*?!") {
					continue
				}
				ph := &ParsedHost{Alias: alias, Port: 22, Profile: "imported"}
				current = append(current, ph)
				hosts = append(hosts, ph)
			}
		case keyword == "match":
			current = nil
		case keyword == "include" && baseDir != "":
			hosts = append(hosts, parseIncludes(value, baseDir, seen)...)
			current = nil
		default:
			for _, ph := range current {
				applyOption(ph, keyword, value)
			}
		}
	}
	return hosts
}

// splitKV splits a config line into a lowercased keyword and the trimmed rest,
// mirroring Python's line.split(None, 1) (whitespace only; no "=" handling).
func splitKV(line string) (string, string) {
	i := strings.IndexFunc(line, unicode.IsSpace)
	if i < 0 {
		return strings.ToLower(line), ""
	}
	return strings.ToLower(line[:i]), strings.TrimSpace(line[i:])
}

func applyOption(h *ParsedHost, keyword, value string) {
	switch keyword {
	case "hostname":
		h.Hostname = value
	case "user":
		h.User = value
	case "port":
		if n, err := strconv.Atoi(value); err == nil {
			h.Port = n
		}
	case "identityfile":
		h.IdentityFile = value
		h.Profile = profileFromIdentity(value)
	default:
		if manifest.IsDangerousOption(keyword) {
			return // drop command/config-executing directives
		}
		if !simpleKeys[keyword] {
			h.Extra = append(h.Extra, kv{keyword, value})
		}
	}
}

func profileFromIdentity(identityFile string) string {
	parts := strings.Split(filepath.ToSlash(identityFile), "/")
	for i, p := range parts {
		if p == "profiles" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "imported"
}

func parseIncludes(pattern, baseDir string, seen map[string]bool) []*ParsedHost {
	var hosts []*ParsedHost
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
			hosts = append(hosts, parseSSHConfig(string(b), baseDir, seen)...)
		}
	}
	return hosts
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
	type rh struct {
		h   *ParsedHost
		res resolution
	}
	var resolved []rh
	seen := map[string]bool{}
	for _, h := range parsed {
		k := h.Profile + "\x00" + h.Alias
		if seen[k] {
			continue // duplicate Host block in the source - first wins
		}
		seen[k] = true
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
		byProfile[h.Profile] = append(byProfile[h.Profile], host)
	}
	for _, name := range order {
		m.SetProfile(name, manifest.Profile{KeyScope: "per_service", Hosts: byProfile[name]})
	}

	inv := inventory.New()
	adopted := 0
	for _, r := range resolved {
		ident := m.IdentityFile(r.h.Profile, r.res.keyName)
		if !dryRun && r.res.adoptFrom != "" && im.adoptKey(r.res.adoptFrom, r.h.Profile, r.res.keyName) {
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

	result := ImportResult{DryRun: dryRun, KeysFound: len(inv.Keys), Adopted: adopted, Profiles: map[string]int{}}
	for _, h := range parsed {
		result.Profiles[h.Profile]++
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
	parts := strings.Split(filepath.ToSlash(real), "/")
	for i, p := range parts {
		if p == "profiles" && i+1 < len(parts) {
			return parts[i+1] == profile
		}
	}
	return false
}

// adoptKey copies an existing keypair into profiles/<profile>/<keyName>.
// Non-destructive: skips if the destination already exists.
func (im *Importer) adoptKey(srcPriv, profile, keyName string) bool {
	dstPriv := filepath.Join(im.p.SSHDir, "profiles", profile, keyName)
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

func expanduser(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
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
