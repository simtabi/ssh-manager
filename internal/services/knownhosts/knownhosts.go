// Package knownhosts pins host keys via ssh-keyscan, ported from
// services/knownhosts.py + facade.{known_hosts_targets,init_known_hosts}. It scans
// and fingerprints host keys (data; the surface confirms before trust) and appends
// confirmed lines, deduped, with the right perms - into the single, user-wide
// ~/.ssh/known_hosts trust store every rendered host block points at.
//
// Every line sshmgr writes carries a trailing "sshmgr" comment tag (see
// sshd(8)'s "marker hostnames keytype key comment" line format). That tag is
// what makes cleanup safe: prune only removes tagged lines, and only once no
// remaining manifest host resolves to that host:port, so deleting one profile
// can never strand or unpin a host another profile still uses. Untagged lines
// - anything the user or another tool pinned - are never touched unless
// explicitly adopted.
package knownhosts

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/netcheck"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// knownHostsMode is owner-only. A trust store is not a public key file: it is the
// list of every host the user connects to, and hashing the names only helps if the
// file is not readable by other local accounts in the first place.
const knownHostsMode = perms.KnownHostsMode

// ScannedKey is one host key returned by ssh-keyscan, with its fingerprint.
type ScannedKey struct {
	Host        string
	Port        int
	Keytype     string
	Line        string
	Fingerprint string
}

// Service manages the single, user-wide known_hosts trust store.
type Service struct {
	sshDir string
}

// New builds a known-hosts service over ~/.ssh.
func New(sshDir string) *Service { return &Service{sshDir: sshDir} }

// Path is the one trust store every profile's hosts are pinned into.
func (s *Service) Path() string {
	return filepath.Join(s.sshDir, "known_hosts")
}

// Scan ssh-keyscans a host and fingerprints each key (no writes).
func (s *Service) Scan(host string, port int) []ScannedKey {
	if _, err := exec.LookPath("ssh-keyscan"); err != nil {
		return nil
	}
	args := []string{"-T", "5"}
	if port != 22 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	args = append(args, "--", host) // -- so a hostile hostname can't be an option
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ssh-keyscan", args...).Output()
	var keys []ScannedKey
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		keytype := "?"
		if len(parts) >= 2 {
			keytype = parts[1]
		}
		keys = append(keys, ScannedKey{Host: host, Port: port, Keytype: keytype, Line: line, Fingerprint: fingerprint(line)})
	}
	return keys
}

// Ensure creates known_hosts (empty, correct perms) if absent so the path the
// rendered config references always exists. Returns true if created.
func (s *Service) Ensure() (bool, error) {
	path := s.Path()
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		return false, nil
	}
	if err := fs.WriteTextAtomic(path, "", knownHostsMode); err != nil {
		return false, err
	}
	return true, perms.SetPerms(path, knownHostsMode)
}

// Add appends confirmed host-key lines to the trust store, deduped, atomically.
// Host names are hashed on the way in and every line is tagged as sshmgr-owned.
// Returns the count added.
//
// Dedup cannot be string equality any more. Every hashed line carries a fresh
// random salt, so re-pinning the same host produces different bytes each time and
// a naive comparison would append a duplicate on every run. Membership is decided
// on (host name, key type, key) instead, computing each existing entry's HMAC
// under its own salt.
func (s *Service) Add(lines []string) (int, error) {
	path := s.Path()
	var existing []string
	if b, err := os.ReadFile(path); err == nil {
		existing = splitNonEmptyTrailing(string(b))
	}
	pinned := parseAll(existing)
	// verbatimRaw catches exact-text duplicates (including comments); keyed
	// dedups patterns/markers structurally, since a line re-submitted for
	// tagging is byte-different from what is already on disk (it lacks the
	// tag) but must still not be duplicated.
	verbatimRaw := map[string]bool{}
	keyed := map[string]bool{}
	for _, ln := range existing {
		trimmed := strings.TrimSpace(ln)
		verbatimRaw[trimmed] = true
		if p, ok := parseKHLine(trimmed); ok {
			keyed[lineKey(p)] = true
		}
	}

	var fresh []string
	for _, raw := range lines {
		parsed, ok := parseKHLine(raw)
		if !ok || !hashable(parsed.marker, parsed.field) {
			// Patterns, markers and anything unparseable are kept as-is (hashing a
			// wildcard would leave it matching nothing), but still tagged so they
			// remain eligible for reference-counted pruning like every other line
			// this call writes.
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || verbatimRaw[trimmed] || (ok && keyed[lineKey(parsed)]) {
				continue
			}
			out := trimmed
			if ok && !parsed.tagged() {
				out = trimmed + " " + sshmgrTag
			}
			fresh = append(fresh, out)
			verbatimRaw[out] = true
			if ok {
				keyed[lineKey(parsed)] = true
			}
			continue
		}
		// A plaintext "host,ip" field becomes one line per name: a hashed field
		// holds a single hash and cannot express a list.
		for _, token := range parsed.tokens() {
			if isPinned(pinned, token, parsed.keytype, parsed.key) {
				continue
			}
			field, err := hashHostFresh(token)
			if err != nil {
				return 0, err
			}
			line := field + " " + parsed.keytype + " " + parsed.key + " " + sshmgrTag
			fresh = append(fresh, line)
			pinned = append(pinned, khLine{field: field, keytype: parsed.keytype, key: parsed.key})
		}
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	body := strings.TrimSpace(strings.Join(append(existing, fresh...), "\n")) + "\n"
	if err := fs.WriteTextAtomic(path, body, knownHostsMode); err != nil {
		return 0, err
	}
	if err := perms.SetPerms(path, knownHostsMode); err != nil {
		return 0, err
	}
	return len(fresh), nil
}

func parseAll(lines []string) []khLine {
	var out []khLine
	for _, raw := range lines {
		if parsed, ok := parseKHLine(raw); ok {
			out = append(out, parsed)
		}
	}
	return out
}

// lineKey identifies a parsed line by its meaning (marker, host field, key
// type, key) rather than by its exact bytes, so a candidate line differing
// only by the trailing sshmgr tag is still recognized as the same entry.
func lineKey(p khLine) string {
	return p.marker + "\x00" + p.field + "\x00" + p.keytype + "\x00" + p.key
}

// isPinned reports whether this exact host key is already trusted for token.
func isPinned(pinned []khLine, token, keytype, key string) bool {
	for _, p := range pinned {
		if p.keytype == keytype && p.key == key && hostFieldMatches(p.field, token) {
			return true
		}
	}
	return false
}

func fingerprint(line string) string {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return "?"
	}
	cmd := exec.Command("ssh-keygen", "-lf", "-")
	cmd.Stdin = strings.NewReader(line)
	out, _ := cmd.Output()
	parts := strings.Fields(string(out))
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "SHA256:") {
		return parts[1]
	}
	return "?"
}

// splitNonEmptyTrailing splits text into lines like Python str.splitlines (no
// trailing empty element from a final newline).
func splitNonEmptyTrailing(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// HostInKnownHosts reports whether token (a hostname or [host]:port) is a pinned
// host in path. Shared with doctor.
//
// It has to understand hashed entries as well as plaintext ones. Comparing host
// fields as strings would report every host this tool pinned as unpinned, which
// would send doctor and auto-pin into re-pinning hosts forever.
func HostInKnownHosts(path, token string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		hostField := fields[0]
		if strings.HasPrefix(fields[0], "@") && len(fields) > 1 {
			hostField = fields[1] // @cert-authority/@revoked shifts the host right
		}
		if hostFieldMatches(hostField, token) {
			return true
		}
	}
	return false
}

// Target is one manifest host to pin.
type Target struct {
	Profile  string
	Alias    string
	Hostname string
	Port     int
}

// Targets returns (profile, alias, hostname, port) for every manifest host,
// deduped by (profile, hostname, port). Mirrors facade.known_hosts_targets.
func Targets(m *manifest.Manifest) ([]Target, error) {
	rks, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Target
	for _, rk := range rks {
		key := fmt.Sprintf("%s\x00%s\x00%d", rk.Profile, rk.Host.Hostname, rk.Host.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Target{Profile: rk.Profile, Alias: rk.Host.Alias, Hostname: rk.Host.Hostname, Port: rk.Host.Port})
	}
	return out, nil
}

// ProfileOfAlias returns the profile that defines alias, or "" if none.
func ProfileOfAlias(m *manifest.Manifest, alias string) string {
	rks, err := m.IterResolved()
	if err != nil {
		return ""
	}
	for _, rk := range rks {
		if rk.Host.Alias == alias {
			return rk.Profile
		}
	}
	return ""
}

// HostPinResult is the outcome of initializing one host's known_hosts entry.
type HostPinResult struct {
	Profile      string
	Alias        string
	Hostname     string
	Port         int
	Status       string // pinned | already-trusted | unreachable | no-keys
	Fingerprints []string
}

// InitReport summarizes a knownhosts init run.
type InitReport struct {
	Profiles []string
	Created  []string
	Results  []HostPinResult
}

// Format renders the human-readable init report (mirrors KnownHostsInitReport.format).
func (r InitReport) Format() string {
	lines := []string{fmt.Sprintf("knownhosts init: %d profile(s)", len(r.Profiles))}
	for _, c := range r.Created {
		lines = append(lines, "  created "+c)
	}
	byProfile := map[string][]HostPinResult{}
	var order []string
	for _, res := range r.Results {
		if _, ok := byProfile[res.Profile]; !ok {
			order = append(order, res.Profile)
		}
		byProfile[res.Profile] = append(byProfile[res.Profile], res)
	}
	sort.Strings(order)
	icon := map[string]string{"pinned": "+", "already-trusted": "=", "unreachable": "!", "no-keys": "?"}
	for _, prof := range order {
		lines = append(lines, "  ["+prof+"]")
		for _, res := range byProfile[prof] {
			ic := icon[res.Status]
			if ic == "" {
				ic = " "
			}
			lines = append(lines, fmt.Sprintf("    %s %s (%s:%d) - %s", ic, res.Alias, res.Hostname, res.Port, res.Status))
			for _, fp := range res.Fingerprints {
				lines = append(lines, "        "+fp)
			}
		}
	}
	pinned := 0
	var unreachable []string
	for _, res := range r.Results {
		if res.Status == "pinned" {
			pinned++
		}
		if res.Status == "unreachable" {
			unreachable = append(unreachable, res.Alias)
		}
	}
	tail := ""
	if len(unreachable) > 0 {
		tail = "; unreachable (pin later): " + strings.Join(unreachable, ", ")
	}
	lines = append(lines, fmt.Sprintf("  pinned %d host(s)%s", pinned, tail))
	lines = append(lines, "  review fingerprints above; use `sshmgr knownhosts pin` to confirm-before-trust.")
	return strings.Join(lines, "\n")
}

// Init initializes known_hosts and pins reachable hosts (trust-on-first-use).
// Scope: one profile or allProfiles selects which manifest hosts to scan, not
// which file to write - every host is pinned into the same store. Mirrors
// facade.init_known_hosts. Caller handles the mutation guard (snapshot).
func (s *Service) Init(m *manifest.Manifest, profile string, allProfiles, force bool) (InitReport, error) {
	targets, err := Targets(m)
	if err != nil {
		return InitReport{}, err
	}
	var profs []string
	switch {
	case allProfiles:
		set := map[string]bool{}
		for _, t := range targets {
			set[t.Profile] = true
		}
		for p := range set {
			profs = append(profs, p)
		}
		sort.Strings(profs)
	case profile != "":
		if _, ok := m.Profiles[profile]; !ok {
			return InitReport{}, fmt.Errorf("unknown profile: %q", profile)
		}
		profs = []string{profile}
	default:
		return InitReport{}, fmt.Errorf("give a PROFILE or --all")
	}
	report := InitReport{Profiles: append([]string{}, profs...)}
	inProfs := map[string]bool{}
	for _, p := range profs {
		inProfs[p] = true
	}
	if created, err := s.Ensure(); err != nil {
		return InitReport{}, err
	} else if created {
		report.Created = append(report.Created, "known_hosts")
	}
	for _, t := range targets {
		if inProfs[t.Profile] {
			report.Results = append(report.Results, s.initOne(t.Profile, t.Alias, t.Hostname, t.Port, force))
		}
	}
	return report, nil
}

// autoPinDisabled is true when SSH_MANAGER_AUTO_PIN is set to a falsy string.
func autoPinDisabled(getenv func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv("SSH_MANAGER_AUTO_PIN"))) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

// AutoPin creates/updates each profile's known_hosts with its hosts' keys so a
// freshly minted profile works without a separate pin. Trust-on-first-use only
// (never overrides an already-pinned host), skips unreachable hosts (short 2s
// probe, since the caller holds the lock), and is disabled by SSH_MANAGER_AUTO_PIN
// =0/false/no/off. Returns {profile: keys added}. Mirrors facade._auto_pin.
func (s *Service) AutoPin(m *manifest.Manifest, profiles map[string]bool, getenv func(string) string) map[string]int {
	if autoPinDisabled(getenv) {
		return map[string]int{}
	}
	if _, err := exec.LookPath("ssh-keyscan"); err != nil {
		return map[string]int{}
	}
	rks, err := m.IterResolved()
	if err != nil {
		return map[string]int{}
	}
	added := map[string]int{}
	seen := map[string]bool{}
	for _, rk := range rks {
		if profiles != nil && !profiles[rk.Profile] {
			continue
		}
		h := rk.Host
		key := fmt.Sprintf("%s\x00%s\x00%d", rk.Profile, h.Hostname, h.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		kh := s.Path()
		token := h.Hostname
		if h.Port != 22 {
			token = fmt.Sprintf("[%s]:%d", h.Hostname, h.Port)
		}
		if HostInKnownHosts(kh, token) {
			continue // already trusted - never override
		}
		if !netcheck.TCPReachable(h.Hostname, h.Port, 2*time.Second) {
			continue // unreachable/VPN-gated - pin later
		}
		scanned := s.Scan(h.Hostname, h.Port)
		if len(scanned) == 0 {
			continue
		}
		lines := make([]string, len(scanned))
		for i, sk := range scanned {
			lines[i] = sk.Line
		}
		if n, _ := s.Add(lines); n > 0 {
			added[rk.Profile] += n
		}
	}
	return added
}

func (s *Service) initOne(profile, alias, hostname string, port int, force bool) HostPinResult {
	kh := s.Path()
	token := hostname
	if port != 22 {
		token = fmt.Sprintf("[%s]:%d", hostname, port)
	}
	if !force && HostInKnownHosts(kh, token) {
		return HostPinResult{Profile: profile, Alias: alias, Hostname: hostname, Port: port, Status: "already-trusted"}
	}
	if !netcheck.TCPReachable(hostname, port, 4*time.Second) {
		return HostPinResult{Profile: profile, Alias: alias, Hostname: hostname, Port: port, Status: "unreachable"}
	}
	scanned := s.Scan(hostname, port)
	if len(scanned) == 0 {
		return HostPinResult{Profile: profile, Alias: alias, Hostname: hostname, Port: port, Status: "no-keys"}
	}
	lines := make([]string, len(scanned))
	fps := make([]string, len(scanned))
	for i, sk := range scanned {
		lines[i] = sk.Line
		fps[i] = sk.Keytype + " " + sk.Fingerprint
	}
	_, _ = s.Add(lines)
	return HostPinResult{Profile: profile, Alias: alias, Hostname: hostname, Port: port, Status: "pinned", Fingerprints: fps}
}

// liveTokens is the set of host tokens (hostname, or [hostname]:port for a
// non-default port) every manifest host currently resolves to.
func liveTokens(m *manifest.Manifest) ([]string, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var tokens []string
	for _, rk := range resolved {
		token := rk.Host.Hostname
		if rk.Host.Port != 0 && rk.Host.Port != 22 {
			token = fmt.Sprintf("[%s]:%d", rk.Host.Hostname, rk.Host.Port)
		}
		if !seen[token] {
			seen[token] = true
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

// Prune removes sshmgr-tagged lines that no longer correspond to any manifest
// host. A tagged line survives if any remaining host - in any profile - still
// resolves to its host:port, so deleting one profile's hosts can never strand
// or unpin a host another profile still uses. Untagged lines (the user's own
// pins, or anything else in the file) are never touched. Returns the count
// removed.
func (s *Service) Prune(m *manifest.Manifest) (int, error) {
	live, err := liveTokens(m)
	if err != nil {
		return 0, err
	}
	path := s.Path()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	lines := splitNonEmptyTrailing(string(data))
	kept := make([]string, 0, len(lines))
	removed := 0
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		parsed, ok := parseKHLine(trimmed)
		if !ok || !parsed.tagged() || tokenIsLive(parsed, live) {
			kept = append(kept, raw)
			continue
		}
		removed++
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.rewrite(path, kept)
}

// Adopt tags every untagged line matching a live manifest host, making it
// eligible for future pruning. Opt-in: an untagged pin is presumed to be the
// user's own until they explicitly ask for sshmgr to manage it. Returns the
// count adopted.
func (s *Service) Adopt(m *manifest.Manifest) (int, error) {
	live, err := liveTokens(m)
	if err != nil {
		return 0, err
	}
	path := s.Path()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	lines := splitNonEmptyTrailing(string(data))
	adopted := 0
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		parsed, ok := parseKHLine(trimmed)
		if !ok || parsed.tagged() || !tokenIsLive(parsed, live) {
			continue
		}
		lines[i] = trimmed + " " + sshmgrTag
		adopted++
	}
	if adopted == 0 {
		return 0, nil
	}
	return adopted, s.rewrite(path, lines)
}

func tokenIsLive(parsed khLine, live []string) bool {
	for _, token := range live {
		if hostFieldMatches(parsed.field, token) {
			return true
		}
	}
	return false
}

// MigrationReport summarizes a one-shot migration of legacy per-profile
// known_hosts stores into the single ~/.ssh/known_hosts.
type MigrationReport struct {
	Merged  int      // lines merged in (post-dedup)
	Removed []string // profiles/<name>/known_hosts files deleted, ssh-dir-relative
}

// MigrateLegacyStores merges every profiles/*/known_hosts left over from
// before the trust store consolidated into one file, then deletes them. Lines
// still in plaintext are hashed on the way in, and every merged line is
// tagged, exactly as any other call to Add. A tree with none is a no-op
// (zero merged, zero removed), so callers can run this unconditionally on
// every render without cost once the migration has already happened.
func (s *Service) MigrateLegacyStores() (MigrationReport, error) {
	matches, err := filepath.Glob(filepath.Join(s.sshDir, "profiles", "*", "known_hosts"))
	if err != nil {
		return MigrationReport{}, err
	}
	sort.Strings(matches)
	var report MigrationReport
	for _, legacy := range matches {
		data, readErr := os.ReadFile(legacy)
		if readErr == nil {
			if lines := splitNonEmptyTrailing(string(data)); len(lines) > 0 {
				n, addErr := s.Add(lines)
				if addErr != nil {
					return report, addErr
				}
				report.Merged += n
			}
		}
		if err := os.Remove(legacy); err != nil {
			return report, err
		}
		if rel, err := filepath.Rel(s.sshDir, legacy); err == nil {
			report.Removed = append(report.Removed, filepath.ToSlash(rel))
		}
	}
	return report, nil
}

func (s *Service) rewrite(path string, lines []string) error {
	body := ""
	if len(lines) > 0 {
		body = strings.TrimSpace(strings.Join(lines, "\n")) + "\n"
	}
	if err := fs.WriteTextAtomic(path, body, knownHostsMode); err != nil {
		return err
	}
	return perms.SetPerms(path, knownHostsMode)
}
