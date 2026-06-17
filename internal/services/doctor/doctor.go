// Package doctor diagnoses the install: deps, perms, agent, known_hosts, and
// manifest-vs-disk drift/hygiene. Ported from facade.doctor + its helpers. Every
// on-disk and manifest check mirrors v1 exactly; only the preflight runtime line
// differs (the Go binary has no interpreter dependency).
package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/services/preflight"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// Report is the full doctor diagnosis.
type Report struct {
	Preflight          preflight.Report
	Home               string
	SSHDir             string
	PermIssues         []string
	AgentStatus        string
	KnownHosts         bool
	OldKeys            map[string]int // key_name -> archived count
	ConfigInSync       bool
	OrphanKeys         []string
	DuplicateKeys      []string
	UnpinnedHosts      []string
	AliasCollisions    []string
	ProvidersSource    string // "user file" | "shipped default"
	StrandedLegacyHome string
}

// OK is the overall verdict (mirrors DoctorReport.ok).
func (r Report) OK() bool {
	if !r.Preflight.OK() || len(r.PermIssues) > 0 || !r.ConfigInSync {
		return false
	}
	for _, n := range r.OldKeys {
		if n > 1 {
			return false
		}
	}
	return true
}

// secret modes for the config home (mirrors facade SECRET_DIR/FILE_MODE).
const (
	secretDirMode  os.FileMode = 0o700
	secretFileMode os.FileMode = 0o600
)

// Format renders the human-readable report (mirrors DoctorReport.format; the
// preflight block carries the Go runtime line in place of the Python version).
func (r Report) Format() string {
	lines := []string{preflight.Format(r.Preflight), ""}
	if r.Home != "" {
		lines = append(lines, fmt.Sprintf("home: %s  (config + secrets + logs + snapshots live here)", r.Home))
	}
	if r.SSHDir != "" {
		lines = append(lines, fmt.Sprintf("ssh:  %s  (generated)", r.SSHDir))
	}
	lines = append(lines, "providers: "+r.ProvidersSource)
	if r.StrandedLegacyHome != "" {
		lines = append(lines, fmt.Sprintf("WARNING: a legacy home %s was NOT migrated "+
			"(the standard home already existed). Compare the two, then run "+
			"`sshmgr migrate --force` (backs up the current home and replaces it with "+
			"the legacy one).", r.StrandedLegacyHome))
	}
	lines = append(lines, "agent: "+r.AgentStatus)
	lines = append(lines, "known_hosts: "+presentAbsent(r.KnownHosts))
	if len(r.UnpinnedHosts) > 0 {
		lines = append(lines, "host keys NOT pinned (ssh/git will fail host-key "+
			"verification until these are pinned):")
		for _, h := range r.UnpinnedHosts {
			lines = append(lines, "  "+h)
		}
		lines = append(lines, "  -> run: sshmgr knownhosts pin --all   "+
			"(VPN-gated hosts: connect the VPN first)")
	}
	if len(r.AliasCollisions) > 0 {
		lines = append(lines, "WARNING: the same Host alias is used in >1 profile - ssh "+
			"applies the FIRST match, so the others are shadowed:")
		for _, a := range r.AliasCollisions {
			lines = append(lines, "  "+a)
		}
		lines = append(lines, "  -> give each host a distinct, profile-prefixed alias")
	}
	drift := "none"
	if !r.ConfigInSync {
		drift = "DRIFT (run config render)"
	}
	lines = append(lines, "config drift: "+drift)
	if len(r.PermIssues) > 0 {
		lines = append(lines, "perm issues:")
		for _, p := range r.PermIssues {
			lines = append(lines, "  "+p)
		}
	} else {
		lines = append(lines, "perms: ok")
	}
	var badOld []string
	for _, k := range sortedIntKeys(r.OldKeys) {
		if r.OldKeys[k] > 1 {
			badOld = append(badOld, fmt.Sprintf("%s=%d", k, r.OldKeys[k]))
		}
	}
	if len(badOld) > 0 {
		lines = append(lines, "WARNING: >1 archived predecessor (invariant <=1-old): "+strings.Join(badOld, ", "))
	}
	if len(r.OrphanKeys) > 0 {
		lines = append(lines, "orphaned keys (on disk, not in the manifest):")
		for _, k := range r.OrphanKeys {
			lines = append(lines, "  "+k)
		}
	}
	if len(r.DuplicateKeys) > 0 {
		lines = append(lines, "WARNING: keys reuse the same fingerprint (blast radius): "+strings.Join(r.DuplicateKeys, ", "))
	}
	lines = append(lines, "")
	if r.OK() {
		lines = append(lines, "doctor: clean")
	} else {
		lines = append(lines, "doctor: issues found")
	}
	return strings.Join(lines, "\n")
}

// JSON returns the machine-readable view (mirrors DoctorReport.as_dict key order),
// with empty lists/maps as []/{} and unset paths as null.
func (r Report) JSON() ([]byte, error) {
	strOrNil := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	type doc struct {
		OK                 bool           `json:"ok"`
		Home               *string        `json:"home"`
		SSHDir             *string        `json:"ssh_dir"`
		ProvidersSource    string         `json:"providers_source"`
		PreflightOK        bool           `json:"preflight_ok"`
		Agent              string         `json:"agent"`
		KnownHosts         bool           `json:"known_hosts"`
		ConfigInSync       bool           `json:"config_in_sync"`
		PermIssues         []string       `json:"perm_issues"`
		OldKeys            map[string]int `json:"old_keys"`
		OrphanKeys         []string       `json:"orphan_keys"`
		DuplicateKeys      []string       `json:"duplicate_keys"`
		UnpinnedHosts      []string       `json:"unpinned_hosts"`
		AliasCollisions    []string       `json:"alias_collisions"`
		StrandedLegacyHome *string        `json:"stranded_legacy_home"`
	}
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	old := r.OldKeys
	if old == nil {
		old = map[string]int{}
	}
	return jsonIndent(doc{
		OK: r.OK(), Home: strOrNil(r.Home), SSHDir: strOrNil(r.SSHDir),
		ProvidersSource: r.ProvidersSource, PreflightOK: r.Preflight.OK(),
		Agent: r.AgentStatus, KnownHosts: r.KnownHosts, ConfigInSync: r.ConfigInSync,
		PermIssues: nz(r.PermIssues), OldKeys: old, OrphanKeys: nz(r.OrphanKeys),
		DuplicateKeys: nz(r.DuplicateKeys), UnpinnedHosts: nz(r.UnpinnedHosts),
		AliasCollisions: nz(r.AliasCollisions), StrandedLegacyHome: strOrNil(r.StrandedLegacyHome),
	})
}

// FixPerms re-asserts canonical perms on the tool-managed ~/.ssh paths and the
// config-home secrets, returning the paths it changed. Mirrors facade.fix_perms
// (the advisory lock is the Facade's mutation guard, not yet ported).
func (s *Service) FixPerms() []string {
	var changed []string
	for _, mp := range perms.IterManagedPaths(s.p.SSHDir) {
		if !perms.PermsOK(mp.Path, mp.Mode) {
			_ = perms.SetPerms(mp.Path, mp.Mode)
			changed = append(changed, fmt.Sprintf("%s -> %o", mp.Path, uint32(mp.Mode.Perm())))
		}
	}
	for _, sp := range s.secretPerms() {
		if fs.Exists(sp.Path) && !perms.PermsOK(sp.Path, sp.Mode) {
			_ = perms.SetPerms(sp.Path, sp.Mode)
			changed = append(changed, fmt.Sprintf("%s -> %o", sp.Path, uint32(sp.Mode.Perm())))
		}
	}
	return changed
}

func (s *Service) secretPerms() []perms.ManagedPath {
	p := s.p
	items := []perms.ManagedPath{
		{Path: p.ConfigDir, Mode: secretDirMode}, {Path: p.LogDir(), Mode: secretDirMode},
		{Path: p.StateDir(), Mode: secretDirMode}, {Path: p.SnapshotsDir(), Mode: secretDirMode},
		{Path: p.DistDir(), Mode: secretDirMode}, {Path: p.EnvFile(), Mode: secretFileMode},
		{Path: p.AgeIdentity(), Mode: secretFileMode}, {Path: p.AuditLog(), Mode: secretFileMode},
		{Path: p.LockFile(), Mode: secretFileMode},
	}
	for _, pat := range []string{
		filepath.Join(p.DistDir(), "*.age"),
		filepath.Join(p.ConfigDir, "*.age"),
		filepath.Join(p.ConfigDir, "*-identity.txt"),
		filepath.Join(p.SnapshotsDir(), "ssh-*.tar.gz"),
	} {
		matches, _ := filepath.Glob(pat)
		sort.Strings(matches)
		for _, m := range matches {
			items = append(items, perms.ManagedPath{Path: m, Mode: secretFileMode})
		}
	}
	return items
}

// Service runs doctor over a resolved home + (optional) manifest.
type Service struct {
	p               paths.Paths
	m               *manifest.Manifest // nil when no/invalid manifest -> drift checks skipped
	emitUseKeychain bool
}

// New builds a doctor service. m may be nil (no manifest yet).
func New(p paths.Paths, m *manifest.Manifest, emitUseKeychain bool) *Service {
	return &Service{p: p, m: m, emitUseKeychain: emitUseKeychain}
}

// Run gathers the full report.
func (s *Service) Run() Report {
	rep := Report{
		Preflight:       preflight.Check(),
		Home:            s.p.ConfigDir,
		SSHDir:          s.p.SSHDir,
		ProvidersSource: s.providersSource(),
		ConfigInSync:    true,
		OldKeys:         map[string]int{},
	}
	if legacy := s.firstLegacyHome(); legacy != "" && fs.Exists(s.p.ConfigDir) {
		rep.StrandedLegacyHome = legacy
	}
	ssh := s.p.SSHDir
	rep.PermIssues = permIssues(ssh)
	rep.AgentStatus = agentStatus()
	rep.KnownHosts = knownHostsPresent(ssh)
	rep.OldKeys = oldKeyCounts(ssh)
	if s.m != nil {
		if chk, err := configsvc.New(ssh, s.m, s.emitUseKeychain).Check(false); err == nil {
			rep.ConfigInSync = chk.InSync()
		}
		rep.OrphanKeys = s.orphanKeys(ssh)
		rep.DuplicateKeys = duplicateKeys(ssh)
		rep.UnpinnedHosts = s.unpinnedHosts(ssh)
		rep.AliasCollisions = aliasCollisions(s.m)
	}
	return rep
}

func (s *Service) providersSource() string {
	if fs.Exists(s.p.Providers()) {
		return "user file"
	}
	return "shipped default"
}

// firstLegacyHome returns the first real pre-rename/pre-XDG home worth migrating
// (the "sshmgr" sibling of the new home, or ~/.sshmgr), else "".
func (s *Service) firstLegacyHome() string {
	home, _ := os.UserHomeDir()
	cands := []string{
		filepath.Join(filepath.Dir(s.p.ConfigDir), "sshmgr"),
		filepath.Join(home, ".sshmgr"),
	}
	for _, c := range cands {
		if c == s.p.ConfigDir {
			continue
		}
		fi, err := os.Lstat(c)
		if err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			return c
		}
	}
	return ""
}

func permIssues(ssh string) []string {
	var issues []string
	for _, mp := range perms.IterManagedPaths(ssh) {
		if perms.PermsOK(mp.Path, mp.Mode) {
			continue
		}
		fi, err := os.Lstat(mp.Path)
		if err != nil {
			continue
		}
		issues = append(issues, fmt.Sprintf("%s: %o (want %o)",
			mp.Path, uint32(fi.Mode().Perm()), uint32(mp.Mode.Perm())))
	}
	return issues
}

func agentStatus() string {
	if _, err := exec.LookPath("ssh-add"); err != nil {
		return "ssh-add not found"
	}
	out, err := exec.Command("ssh-add", "-l").Output()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	switch code {
	case 0:
		n := 0
		if t := strings.TrimSpace(string(out)); t != "" {
			n = len(strings.Split(t, "\n"))
		}
		return fmt.Sprintf("running, %d key(s) loaded", n)
	case 1:
		return "running, no identities loaded"
	default:
		return "not running"
	}
}

func knownHostsPresent(ssh string) bool {
	if fs.Exists(filepath.Join(ssh, "known_hosts")) {
		return true
	}
	matches, _ := filepath.Glob(filepath.Join(ssh, "profiles", "*", "known_hosts"))
	return len(matches) > 0
}

func oldKeyCounts(ssh string) map[string]int {
	counts := map[string]int{}
	olds, _ := filepath.Glob(filepath.Join(ssh, "profiles", "*", "old"))
	sort.Strings(olds)
	for _, old := range olds {
		fi, err := os.Stat(old)
		if err != nil || !fi.IsDir() {
			continue
		}
		entries, _ := os.ReadDir(old)
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
				continue
			}
			counts[e.Name()]++
		}
	}
	return counts
}

func (s *Service) orphanKeys(ssh string) []string {
	referenced := map[string]bool{}
	if rks, err := s.m.IterResolved(); err == nil {
		for _, rk := range rks {
			referenced[rk.KeyName] = true
		}
	}
	profDir := filepath.Join(ssh, "profiles")
	if !isDir(profDir) {
		return nil
	}
	privs, _ := filepath.Glob(filepath.Join(profDir, "*", "*"))
	sort.Strings(privs)
	var orphans []string
	for _, priv := range privs {
		base := filepath.Base(priv)
		fi, err := os.Lstat(priv)
		if err != nil || fi.IsDir() || strings.HasSuffix(base, ".pub") ||
			base == "config" || strings.HasPrefix(base, ".") {
			continue
		}
		if !fs.Exists(priv + ".pub") {
			continue
		}
		if !referenced[base] {
			rel, _ := filepath.Rel(ssh, priv)
			orphans = append(orphans, filepath.ToSlash(rel))
		}
	}
	return orphans
}

func duplicateKeys(ssh string) []string {
	profDir := filepath.Join(ssh, "profiles")
	if !isDir(profDir) {
		return nil
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return nil
	}
	ks := keystore.New()
	byFP := map[string][]string{}
	var order []string // first-encounter fp order (pubs sorted), to match Python dict order
	pubs, _ := filepath.Glob(filepath.Join(profDir, "*", "*.pub"))
	sort.Strings(pubs)
	for _, pub := range pubs {
		fp, err := ks.Fingerprint(pub)
		if err != nil {
			continue
		}
		if _, seen := byFP[fp]; !seen {
			order = append(order, fp)
		}
		byFP[fp] = append(byFP[fp], strings.TrimSuffix(filepath.Base(pub), ".pub"))
	}
	var dups []string
	for _, fp := range order {
		names := byFP[fp]
		if len(names) > 1 {
			sort.Strings(names)
			dups = append(dups, strings.Join(names, " = "))
		}
	}
	return dups
}

func (s *Service) unpinnedHosts(ssh string) []string {
	rks, err := s.m.IterResolved()
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, rk := range rks {
		h := rk.Host
		key := fmt.Sprintf("%s\x00%s\x00%d", rk.Profile, h.Hostname, h.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		kh := filepath.Join(ssh, "profiles", rk.Profile, "known_hosts")
		token := h.Hostname
		if h.Port != 22 {
			token = fmt.Sprintf("[%s]:%d", h.Hostname, h.Port)
		}
		if !hostInKnownHosts(kh, token) {
			out = append(out, fmt.Sprintf("%s (%s)", h.Alias, h.Hostname))
		}
	}
	return out
}

func aliasCollisions(m *manifest.Manifest) []string {
	where := map[string][]string{}
	for pname, prof := range m.Profiles {
		for _, h := range prof.Hosts {
			where[h.Alias] = append(where[h.Alias], pname)
		}
	}
	aliases := make([]string, 0, len(where))
	for a := range where {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	var out []string
	for _, alias := range aliases {
		uniq := sortedUnique(where[alias])
		if len(uniq) > 1 {
			out = append(out, fmt.Sprintf("%s (profiles: %s)", alias, strings.Join(uniq, ", ")))
		}
	}
	return out
}

// hostInKnownHosts reports whether token (a hostname or [host]:port) is a pinned
// host in path. Mirrors facade._host_in_known_hosts.
func hostInKnownHosts(path, token string) bool {
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

func sortedUnique(xs []string) []string {
	set := map[string]bool{}
	for _, x := range xs {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func presentAbsent(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

func sortedIntKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
