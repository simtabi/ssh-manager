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
	"strconv"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/services/preflight"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/homeperms"
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
	StaleOldKeys       []string       // archived predecessors past the retention window
	ConfigInSync       bool
	OrphanKeys         []string
	Dangling           keyaudit.Report
	DuplicateKeys      []string
	UnpinnedHosts      []string
	AliasCollisions    []string
	ProvidersSource    string // "user file" | "shipped default"
	StrandedLegacyHome string
}

// OK is the overall verdict.
//
// Dangling keys count. They used to be printed and then ignored by the verdict,
// so doctor could list an orphaned key and still say "clean" - a check whose
// result nothing acts on is not a check. Which states are fatal is keyaudit's
// call, not this one's (--strict makes all of them fatal).
func (r Report) OK() bool {
	if !r.Preflight.OK() || len(r.PermIssues) > 0 || !r.ConfigInSync {
		return false
	}
	if !r.Dangling.OK() {
		return false
	}
	for _, n := range r.OldKeys {
		if n > 1 {
			return false
		}
	}
	return true
}

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
	if len(r.StaleOldKeys) > 0 {
		lines = append(lines, "archived predecessors past the retention window "+
			"(unencrypted private keys nobody is using):")
		for _, k := range r.StaleOldKeys {
			lines = append(lines, "  "+k)
		}
		lines = append(lines, "  -> remove them once the rotation is confirmed good "+
			"(keep them longer with SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS)")
	}
	lines = append(lines, r.Dangling.Lines()...)
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
		StaleOldKeys       []string       `json:"stale_old_keys"`
		OrphanKeys         []string       `json:"orphan_keys"`
		DanglingKeys       []danglingJSON `json:"dangling_keys"`
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
		PermIssues: nz(r.PermIssues), OldKeys: old, StaleOldKeys: nz(r.StaleOldKeys),
		OrphanKeys: nz(r.OrphanKeys), DanglingKeys: danglingRows(r.Dangling),
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
	for _, sp := range homeperms.SecretPerms(s.p) {
		if fs.Exists(sp.Path) && !perms.PermsOK(sp.Path, sp.Mode) {
			_ = perms.SetPerms(sp.Path, sp.Mode)
			changed = append(changed, fmt.Sprintf("%s -> %o", sp.Path, uint32(sp.Mode.Perm())))
		}
	}
	return changed
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

// Run gathers the full report. strict escalates every dangling-key state to
// fatal, for CI.
func (s *Service) Run(strict bool) Report {
	rep := Report{
		Preflight:       preflight.Check(),
		Home:            s.p.ConfigDir,
		SSHDir:          s.p.SSHDir,
		ProvidersSource: s.providersSource(),
		ConfigInSync:    true,
		OldKeys:         map[string]int{},
	}
	if legacy := s.p.FirstLegacyHome(); legacy != "" && fs.Exists(s.p.ConfigDir) {
		rep.StrandedLegacyHome = legacy
	}
	ssh := s.p.SSHDir
	rep.PermIssues = permIssues(ssh, s.p)
	rep.AgentStatus = agentStatus()
	rep.KnownHosts = knownHostsPresent(ssh)
	rep.OldKeys, rep.StaleOldKeys = archivedKeys(ssh, OldKeyMaxAge(nil), time.Now())
	if s.m != nil {
		if chk, err := configsvc.New(ssh, s.m, s.emitUseKeychain).Check(false); err == nil {
			rep.ConfigInSync = chk.InSync()
		}
		rep.Dangling = s.dangling(strict)
		// orphan_keys stays in the JSON as the untracked view of the same audit:
		// same meaning as before, now without the .pub requirement that hid the
		// worst cases.
		for _, f := range rep.Dangling.ByState(keyaudit.Untracked) {
			rep.OrphanKeys = append(rep.OrphanKeys, f.Subject)
		}
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

// permIssues walks exactly what FixPerms repairs, config home included. The two
// used to disagree: FixPerms tightened the config home while the check only
// looked at ~/.ssh, so a world-readable manifest or providers.json was silently
// repaired but never reported, and doctor called it clean.
func permIssues(ssh string, p paths.Paths) []string {
	var issues []string
	report := func(mp perms.ManagedPath) {
		if perms.PermsOK(mp.Path, mp.Mode) {
			return
		}
		fi, err := os.Lstat(mp.Path)
		if err != nil {
			return
		}
		issues = append(issues, fmt.Sprintf("%s: %o (want %o)",
			mp.Path, uint32(fi.Mode().Perm()), uint32(mp.Mode.Perm())))
	}
	for _, mp := range perms.IterManagedPaths(ssh) {
		report(mp)
	}
	for _, mp := range homeperms.SecretPerms(p) {
		if fs.Exists(mp.Path) {
			report(mp)
		}
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
	return fs.Exists(filepath.Join(ssh, "known_hosts"))
}

// DefaultOldKeyMaxAge is how long an archived predecessor is considered useful.
// Past that, the rotation it belongs to has long since been verified in practice
// and the file is just an unencrypted private key nobody is watching.
const DefaultOldKeyMaxAge = 90 * 24 * time.Hour

// OldKeyMaxAge is the staleness threshold, overridable with
// $SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS. A value of 0 or less disables the check
// rather than marking everything stale, so the escape hatch is not a footgun.
func OldKeyMaxAge(get func(string) string) time.Duration {
	if get == nil {
		get = os.Getenv
	}
	raw := strings.TrimSpace(get("SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS"))
	if raw == "" {
		return DefaultOldKeyMaxAge
	}
	days, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultOldKeyMaxAge
	}
	if days <= 0 {
		return 0
	}
	return time.Duration(days) * 24 * time.Hour
}

// archivedKeys walks profiles/*/old/ once and returns both the per-key archive
// count and the entries older than maxAge. They share a walk so the count and the
// staleness verdict can never describe different sets of files. maxAge 0 skips
// the staleness pass. Paths are relative to ssh, for display.
func archivedKeys(ssh string, maxAge time.Duration, now time.Time) (map[string]int, []string) {
	counts := map[string]int{}
	var stale []string
	olds, _ := filepath.Glob(filepath.Join(ssh, "profiles", "*", "old"))
	sort.Strings(olds)
	for _, old := range olds {
		fi, err := os.Stat(old)
		if err != nil || !fi.IsDir() {
			continue
		}
		profile := filepath.Base(filepath.Dir(old))
		entries, _ := os.ReadDir(old)
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
				continue
			}
			// Counted per profile: merging same-named archives from two profiles
			// would falsely trip the "more than one predecessor" check.
			counts[profile+"/"+e.Name()]++
			if maxAge <= 0 {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if age := now.Sub(info.ModTime()); age > maxAge {
				stale = append(stale, fmt.Sprintf("%s/old/%s (%d days old)",
					profile, e.Name(), int(age.Hours()/24)))
			}
		}
	}
	sort.Strings(stale)
	return counts, stale
}

// dangling runs the key audit. A missing/unreadable inventory is not fatal here:
// doctor's job is to report the state of a broken install, so it audits with an
// empty inventory rather than refusing to run - every key then reads as
// unrecorded, which is the truth.
func (s *Service) dangling(strict bool) keyaudit.Report {
	inv, err := inventory.Load(s.p.Inventory())
	if err != nil {
		inv = inventory.New()
	}
	rep, err := keyaudit.New(s.m, inv, s.p.SSHDir).Audit(strict)
	if err != nil {
		return keyaudit.Report{Strict: strict}
	}
	return rep
}

// danglingJSON is one finding in the machine-readable report.
type danglingJSON struct {
	State    string `json:"state"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
	Blocking bool   `json:"blocking"`
}

func danglingRows(rep keyaudit.Report) []danglingJSON {
	out := make([]danglingJSON, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, danglingJSON{
			State: f.State, Subject: f.Subject, Detail: f.Detail, Fix: f.Fix,
			Blocking: rep.Strict || keyaudit.Blocking(f.State),
		})
	}
	return out
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
		name := strings.TrimSuffix(filepath.Base(pub), ".pub")
		byFP[fp] = append(byFP[fp], filepath.Base(filepath.Dir(pub))+"/"+name)
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
		kh := filepath.Join(ssh, "known_hosts")
		token := h.Hostname
		if h.Port != 22 {
			token = fmt.Sprintf("[%s]:%d", h.Hostname, h.Port)
		}
		if !knownhosts.HostInKnownHosts(kh, token) {
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
