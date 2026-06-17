// Package knownhosts pins host keys via ssh-keyscan, ported from
// services/knownhosts.py + facade.{known_hosts_targets,init_known_hosts}. It scans
// and fingerprints host keys (data; the surface confirms before trust) and appends
// confirmed lines, deduped, with the right perms - per-profile trust stores plus
// an optional aggregate user store.
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

// UserStore is the report label for the top-level ~/.ssh/known_hosts. An empty
// profile string everywhere else denotes that same user store.
const UserStore = "(user)"

const knownHostsMode os.FileMode = 0o644

// ScannedKey is one host key returned by ssh-keyscan, with its fingerprint.
type ScannedKey struct {
	Host        string
	Port        int
	Keytype     string
	Line        string
	Fingerprint string
}

// Service manages the per-profile and user known_hosts trust stores.
type Service struct {
	sshDir string
}

// New builds a known-hosts service over ~/.ssh.
func New(sshDir string) *Service { return &Service{sshDir: sshDir} }

// PathFor is the trust store for a profile, or the top-level user store when
// profile is "".
func (s *Service) PathFor(profile string) string {
	if profile == "" {
		return filepath.Join(s.sshDir, "known_hosts")
	}
	return filepath.Join(s.sshDir, "profiles", profile, "known_hosts")
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

// Ensure creates the profile's known_hosts (empty, correct perms) if absent so the
// path the rendered config references always exists. Returns true if created.
func (s *Service) Ensure(profile string) (bool, error) {
	path := s.PathFor(profile)
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		return false, nil
	}
	if err := fs.WriteTextAtomic(path, "", knownHostsMode); err != nil {
		return false, err
	}
	return true, perms.SetPerms(path, knownHostsMode)
}

// Add appends confirmed host-key lines to a trust store, deduped, atomically.
// Returns the count added.
func (s *Service) Add(lines []string, profile string) (int, error) {
	path := s.PathFor(profile)
	var existing []string
	if b, err := os.ReadFile(path); err == nil {
		existing = splitNonEmptyTrailing(string(b))
	}
	seen := map[string]bool{}
	for _, ln := range existing {
		seen[ln] = true
	}
	var fresh []string
	for _, ln := range lines {
		if !seen[ln] {
			fresh = append(fresh, ln)
			seen[ln] = true
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
// host in path. Mirrors facade._host_in_known_hosts; shared with doctor.
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
		for _, h := range strings.Split(hostField, ",") {
			if h == token {
				return true
			}
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
// Scope: one profile or allProfiles, and/or the user store. Mirrors
// facade.init_known_hosts. Caller handles the mutation guard (snapshot).
func (s *Service) Init(m *manifest.Manifest, profile string, allProfiles, user, force bool) (InitReport, error) {
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
	}
	if len(profs) == 0 && !user {
		return InitReport{}, fmt.Errorf("give a PROFILE, --all, or --user")
	}
	report := InitReport{Profiles: append([]string{}, profs...)}
	if user {
		report.Profiles = append(report.Profiles, UserStore)
	}
	inProfs := map[string]bool{}
	for _, p := range profs {
		inProfs[p] = true
	}
	for _, prof := range profs {
		if created, err := s.Ensure(prof); err != nil {
			return InitReport{}, err
		} else if created {
			report.Created = append(report.Created, "profiles/"+prof+"/known_hosts")
		}
	}
	for _, t := range targets {
		if inProfs[t.Profile] {
			report.Results = append(report.Results, s.initOne(t.Profile, t.Alias, t.Hostname, t.Port, force))
		}
	}
	if user {
		if created, err := s.Ensure(""); err != nil {
			return InitReport{}, err
		} else if created {
			report.Created = append(report.Created, "known_hosts")
		}
		seen := map[string]bool{}
		for _, t := range targets {
			key := fmt.Sprintf("%s\x00%d", t.Hostname, t.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			report.Results = append(report.Results, s.initOne("", t.Alias, t.Hostname, t.Port, force))
		}
	}
	return report, nil
}

func (s *Service) initOne(profile, alias, hostname string, port int, force bool) HostPinResult {
	label := profile
	if label == "" {
		label = UserStore
	}
	kh := s.PathFor(profile)
	token := hostname
	if port != 22 {
		token = fmt.Sprintf("[%s]:%d", hostname, port)
	}
	if !force && HostInKnownHosts(kh, token) {
		return HostPinResult{Profile: label, Alias: alias, Hostname: hostname, Port: port, Status: "already-trusted"}
	}
	if !netcheck.TCPReachable(hostname, port, 4*time.Second) {
		return HostPinResult{Profile: label, Alias: alias, Hostname: hostname, Port: port, Status: "unreachable"}
	}
	scanned := s.Scan(hostname, port)
	if len(scanned) == 0 {
		return HostPinResult{Profile: label, Alias: alias, Hostname: hostname, Port: port, Status: "no-keys"}
	}
	lines := make([]string, len(scanned))
	fps := make([]string, len(scanned))
	for i, sk := range scanned {
		lines[i] = sk.Line
		fps[i] = sk.Keytype + " " + sk.Fingerprint
	}
	_, _ = s.Add(lines, profile)
	return HostPinResult{Profile: label, Alias: alias, Hostname: hostname, Port: port, Status: "pinned", Fingerprints: fps}
}
