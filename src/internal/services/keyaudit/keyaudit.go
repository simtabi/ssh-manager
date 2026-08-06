// Package keyaudit is the one definition of what "dangling" means for a key.
//
// A key can go wrong in seven ways, and each one used to be either undetected or
// detected differently by whoever happened to look. doctor called a tree clean
// while listing orphans; a key file with no .pub - the most dangling artifact
// possible - was skipped by the orphan check precisely because it had no .pub;
// nothing at all noticed a key the manifest declared but no host used, or an
// inventory record pointing at a profile that had been deleted. So doctor, `key
// list`, `show`, `clean` and the notifier all read their answer from here.
//
// Everything is decided from the manifest, the inventory and os.Lstat. Private
// key material is never read - only public halves, and only to confirm they are
// public keys.
package keyaudit

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
)

// The seven states a key can dangle in.
const (
	// Untracked: a key file under profiles/ that no manifest profile owns. The
	// tool made it and then lost track of it, or someone put it there.
	Untracked = "untracked"
	// Unwired: owned by a profile, referenced by no host, so it is never
	// rendered as an IdentityFile and never actually used by ssh.
	Unwired = "unwired"
	// Missing: the manifest references it, the filesystem does not have it.
	Missing = "missing"
	// HalfPair: a private key with no .pub, or a .pub with no private key.
	HalfPair = "half-pair"
	// Unrecorded: file and manifest agree, but no inventory record covers it, so
	// expiry and rotation are blind to it.
	Unrecorded = "unrecorded"
	// StaleInventory: a record whose path no manifest key owns any more - it
	// tracks the expiry of something that is gone.
	StaleInventory = "stale-inventory"
	// Loose: a key-shaped file directly under ~/.ssh that no Host block uses.
	// Reported and offered to `import`, never touched: the tool did not create
	// it, which is exactly why it is worth mentioning.
	Loose = "loose"
)

// states in report order: the ones that break something first.
var order = []string{Untracked, Unwired, HalfPair, Missing, Unrecorded, StaleInventory, Loose}

// blocking states make a tree not-OK rather than merely worth mentioning.
//
// Missing is deliberately not one of them: it is the normal state of a key
// between `host add` and the reconcile that mints it, so failing on it would
// make doctor red during ordinary work. The three that do block are all states
// where a key exists but nothing will ever use it, or exists only halfway - none
// of which resolve by carrying on.
var blocking = map[string]bool{Untracked: true, Unwired: true, HalfPair: true}

// Blocking reports whether a state makes the audit fail rather than warn.
func Blocking(state string) bool { return blocking[state] }

// Finding is one dangling artifact.
type Finding struct {
	State   string
	Subject string // "profile/key", a path relative to ~/.ssh, or a fingerprint
	Detail  string // what is actually wrong, in one clause
	Fix     string // the command that resolves it, if there is one
}

// Report is everything the audit found.
type Report struct {
	Findings []Finding
	// Strict escalates every state to blocking, for CI - where a warning nobody
	// reads is the same as no check at all.
	Strict bool
}

// OK is the verdict: no blocking findings, or under Strict, no findings at all.
func (r Report) OK() bool {
	for _, f := range r.Findings {
		if r.Strict || Blocking(f.State) {
			return false
		}
	}
	return true
}

// Counts is findings per state, for a one-line summary.
func (r Report) Counts() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.State]++
	}
	return out
}

// ByState returns the findings in one state.
func (r Report) ByState(state string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.State == state {
			out = append(out, f)
		}
	}
	return out
}

// Summary is the counts as one line, worst state first ("" when nothing dangles).
func (r Report) Summary() string {
	counts := r.Counts()
	var parts []string
	for _, state := range order {
		if n := counts[state]; n > 0 {
			parts = append(parts, state+"="+strconv.Itoa(n))
		}
	}
	return strings.Join(parts, " ")
}

// Lines renders the report as a grouped block, each finding carrying its fix.
func (r Report) Lines() []string {
	if len(r.Findings) == 0 {
		return nil
	}
	lines := []string{"dangling keys:"}
	for _, state := range order {
		found := r.ByState(state)
		if len(found) == 0 {
			continue
		}
		marker := ""
		if r.Strict || Blocking(state) {
			marker = "  (fails doctor)"
		}
		lines = append(lines, "  "+state+marker+":")
		for _, f := range found {
			line := "    " + f.Subject
			if f.Detail != "" {
				line += " - " + f.Detail
			}
			lines = append(lines, line)
			if f.Fix != "" {
				lines = append(lines, "      -> "+f.Fix)
			}
		}
	}
	return lines
}

// Notes lists the states one manifest key is in, worst first. This is the
// per-key view `key list` and `show` mark each row with; the states are the same
// ones the audit reports, so a key never reads as fine in one command and
// dangling in another.
func Notes(row keysvc.Row) []string {
	var out []string
	switch {
	case !row.PrivateOnDisk && !row.PublicOnDisk:
		out = append(out, Missing)
	case !row.PrivateOnDisk || !row.PublicOnDisk:
		out = append(out, HalfPair)
	}
	if row.PrivateOnDisk && !row.Recorded {
		out = append(out, Unrecorded)
	}
	if !row.Wired() {
		out = append(out, Unwired)
	}
	return out
}

// Service audits one ~/.ssh tree against its manifest and inventory.
type Service struct {
	m      *manifest.Manifest
	inv    *inventory.Inventory
	sshDir string
	keys   *keysvc.Service
}

// New builds an audit service.
func New(m *manifest.Manifest, inv *inventory.Inventory, sshDir string) *Service {
	return &Service{m: m, inv: inv, sshDir: sshDir, keys: keysvc.New(m, inv, sshDir)}
}

// Audit walks the manifest, the inventory and the tree, and returns every
// dangling artifact found. Findings are grouped by state in severity order and
// sorted within a state, so two runs over the same tree report identically.
func (s *Service) Audit(strict bool) (Report, error) {
	rep := Report{Strict: strict}
	rows, err := s.keys.Rows("")
	if err != nil {
		return rep, err
	}
	owned := map[manifest.KeyRef]bool{}
	for _, row := range rows {
		owned[row.Ref] = true
		for _, state := range Notes(row) {
			rep.Findings = append(rep.Findings, s.manifestKeyFinding(row, state))
		}
	}
	rep.Findings = append(rep.Findings, s.untracked(owned)...)
	rep.Findings = append(rep.Findings, s.staleInventory()...)
	rep.Findings = append(rep.Findings, s.loose()...)

	rank := map[string]int{}
	for i, state := range order {
		rank[state] = i
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if rank[a.State] != rank[b.State] {
			return rank[a.State] < rank[b.State]
		}
		return a.Subject < b.Subject
	})
	return rep, nil
}

func (s *Service) manifestKeyFinding(row keysvc.Row, state string) Finding {
	f := Finding{State: state, Subject: row.Ref.String()}
	switch state {
	case Missing:
		f.Detail = "the manifest references it; neither half is on disk"
		f.Fix = "sshmgr reconcile"
	case HalfPair:
		half := "the private key is missing"
		if row.PrivateOnDisk {
			half = "the .pub is missing"
		}
		f.Detail = half
		f.Fix = "sshmgr validate " + row.Ref.String() + "   (then reconcile, or key delete --purge)"
	case Unrecorded:
		f.Detail = "on disk but in no inventory record, so expiry and rotation ignore it"
		f.Fix = "sshmgr reconcile"
	case Unwired:
		f.Detail = "no host uses it, so it is never an IdentityFile"
		f.Fix = "sshmgr host edit <profile> <alias> --key-name " + row.Ref.KeyName +
			"   (or: sshmgr key delete " + row.Ref.String() + " --purge)"
	}
	return f
}

// untracked finds key files under profiles/ that no manifest key owns. Unlike
// the orphan check it replaces, it does not require a .pub sibling: a private
// key with no public half is the most dangling thing in the tree, and requiring
// the .pub made exactly that case invisible.
func (s *Service) untracked(owned map[manifest.KeyRef]bool) []Finding {
	profiles := filepath.Join(s.sshDir, "profiles")
	entries, err := filepath.Glob(filepath.Join(profiles, "*", "*"))
	if err != nil {
		return nil
	}
	seen := map[manifest.KeyRef]bool{}
	var out []Finding
	for _, path := range entries {
		base := filepath.Base(path)
		fi, err := os.Lstat(path)
		// Directories are old/, .staging and .mint-* - archives and residue, both
		// somebody else's business.
		if err != nil || fi.IsDir() || skipName(base) {
			continue
		}
		ref := manifest.KeyRef{
			Profile: filepath.Base(filepath.Dir(path)),
			KeyName: strings.TrimSuffix(base, ".pub"),
		}
		if owned[ref] || seen[ref] {
			continue
		}
		seen[ref] = true
		rel := filepath.ToSlash(filepath.Join("profiles", ref.Profile, ref.KeyName))
		detail := "no profile declares it"
		if _, ok := s.m.Profiles[ref.Profile]; !ok {
			detail = "profile " + ref.Profile + " is not in the manifest"
		}
		out = append(out, Finding{
			State: Untracked, Subject: rel, Detail: detail,
			Fix: "sshmgr key add " + ref.Profile + " " + ref.KeyName + "   (adopt it), or delete the files",
		})
	}
	return out
}

// staleInventory finds records for paths no manifest key owns. A record for a
// key the manifest owns but disk does not is Missing, not this - reporting it
// under both would double-count the same key.
func (s *Service) staleInventory() []Finding {
	live := map[string]bool{}
	if refs, err := s.m.KeyRefs(); err == nil {
		for _, ref := range refs {
			live[s.m.IdentityFile(ref.Profile, ref.KeyName)] = true
		}
	}
	var out []Finding
	for fp, rec := range s.inv.Keys {
		// Rotation predecessors are archived on purpose, not stale.
		if live[rec.Path] || inventory.IsArchivedPath(rec.Path) {
			continue
		}
		out = append(out, Finding{
			State: StaleInventory, Subject: fp,
			Detail: "tracks " + rec.Path + ", which no manifest key owns",
			Fix:    "sshmgr clean   (removes the record; no key material is touched)",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

// managedInSSHDir are the files that belong directly in ~/.ssh and are not keys.
var managedInSSHDir = map[string]bool{
	"config": true, "known_hosts": true, "known_hosts.old": true,
	"authorized_keys": true, "environment": true, "rc": true, "profiles": true,
}

// loose finds key-shaped files sitting directly in ~/.ssh: the pre-sshmgr keys a
// user already had. Detection is by pairing (a file with a .pub sibling) or by a
// .pub that parses as a public key - never by reading private key material.
func (s *Service) loose() []Finding {
	entries, err := os.ReadDir(s.sshDir)
	if err != nil {
		return nil
	}
	stems := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || managedInSSHDir[name] || skipName(name) {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".pub"):
			body, err := os.ReadFile(filepath.Join(s.sshDir, name))
			if err != nil || !authkeys.IsValidPublicKey(strings.TrimSpace(string(body))) {
				continue
			}
			stems[strings.TrimSuffix(name, ".pub")] = true
		default:
			if _, err := os.Lstat(filepath.Join(s.sshDir, name+".pub")); err == nil {
				stems[name] = true
			}
		}
	}
	out := make([]Finding, 0, len(stems))
	for stem := range stems {
		out = append(out, Finding{
			State: Loose, Subject: stem,
			Detail: "a key in ~/.ssh that no Host block uses",
			Fix:    "sshmgr import   (bring it under management), or leave it alone",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

// skipName filters dotfiles and the legacy per-profile files the layout refactor
// removed, neither of which is a key.
func skipName(base string) bool {
	return strings.HasPrefix(base, ".") || base == "config" || base == "known_hosts"
}
