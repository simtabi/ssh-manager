// Package keysvc is the key-centric read layer: for every key the manifest owns,
// what is on disk for it, which hosts wire it, and where it is deployed. The
// query package answers the same questions host-first (list/view); this one is
// key-first, because a key can now outlive - or precede - any host that uses it.
//
// Read-only, and deliberately shallow on disk: it uses os.Lstat, so a symlink
// planted where a key should be reports as what it is rather than being followed,
// and it never reads private key material.
package keysvc

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/query"
)

// Dangling conditions a key can be in. Phase 5's keyaudit package will own the
// full state machine (adding untracked and loose, which need a directory walk);
// these are the ones decidable from the manifest, the inventory and a stat.
const (
	// Unwired: the profile owns the key but no host references it, so it is
	// never rendered as an IdentityFile and never actually used.
	Unwired = "unwired"
	// Missing: the manifest says the key exists; the filesystem disagrees.
	Missing = "missing"
	// HalfPair: a private key with no .pub, or a .pub with no private key.
	HalfPair = "half-pair"
	// Unrecorded: the key file exists but no inventory record covers it, so
	// expiry and rotation are blind to it.
	Unrecorded = "unrecorded"
)

// Row is one key: what the manifest declares, what the inventory recorded, and
// what is actually on disk.
type Row struct {
	Ref             manifest.KeyRef
	Type            string // resolved: the declared override, else the default
	RotateAfterDays int
	Declared        bool // has an explicit keys[] entry (vs. implied by a host)
	IdentityFile    string
	PrivatePath     string
	PublicPath      string
	PrivateOnDisk   bool
	PublicOnDisk    bool
	Recorded        bool // an inventory record covers this key
	Fingerprint     string
	Created         string
	ExpiresOn       string
	Hosts           []string // aliases wiring this key, in manifest order
	Deployments     []inventory.Deployment
	Status          string // query.NoKey | query.NeedsRedeploy | query.Deployed
}

// Wired reports whether any host references this key.
func (r Row) Wired() bool { return len(r.Hosts) > 0 }

// Notes lists the dangling conditions this key is in, worst first. Empty means
// the key is declared, present as a pair, tracked, and used by a host.
func (r Row) Notes() []string {
	var out []string
	switch {
	case !r.PrivateOnDisk && !r.PublicOnDisk:
		out = append(out, Missing)
	case !r.PrivateOnDisk || !r.PublicOnDisk:
		out = append(out, HalfPair)
	}
	if r.PrivateOnDisk && !r.Recorded {
		out = append(out, Unrecorded)
	}
	if !r.Wired() {
		out = append(out, Unwired)
	}
	return out
}

// Service answers key-centric questions about one ~/.ssh tree.
type Service struct {
	m      *manifest.Manifest
	inv    *inventory.Inventory
	sshDir string
}

// New builds a key service over a manifest, its inventory, and ~/.ssh.
func New(m *manifest.Manifest, inv *inventory.Inventory, sshDir string) *Service {
	return &Service{m: m, inv: inv, sshDir: sshDir}
}

// Rows returns one row per key the manifest owns, in KeyRefs order (profile in
// manifest order, host-derived keys before declared-only ones). selector filters
// by profile, host alias, key name, or the composite "profile/key" form; empty
// means every key. An unmatched selector is an error, so a typo never looks like
// an empty result.
func (s *Service) Rows(selector string) ([]Row, error) {
	refs, err := s.m.KeyRefs()
	if err != nil {
		return nil, err
	}
	var out []Row
	for _, ref := range refs {
		row, err := s.row(ref)
		if err != nil {
			return nil, err
		}
		if !matches(selector, row) {
			continue
		}
		out = append(out, row)
	}
	if len(out) == 0 && selector != "" {
		return nil, errUnknown(selector)
	}
	return out, nil
}

// Row returns the single row for one resolved key reference.
func (s *Service) Row(ref manifest.KeyRef) (Row, error) { return s.row(ref) }

func (s *Service) row(ref manifest.KeyRef) (Row, error) {
	hosts, err := s.m.HostsForKey(ref)
	if err != nil {
		return Row{}, err
	}
	aliases := make([]string, 0, len(hosts))
	for _, h := range hosts {
		aliases = append(aliases, h.Alias)
	}
	_, declared := s.m.KeySpecFor(ref)
	priv := filepath.Join(s.sshDir, "profiles", ref.Profile, ref.KeyName)
	ident := s.m.IdentityFile(ref.Profile, ref.KeyName)
	row := Row{
		Ref:             ref,
		Type:            s.m.KeyTypeFor(ref),
		RotateAfterDays: s.m.RotateAfterDaysFor(ref),
		Declared:        declared,
		IdentityFile:    ident,
		PrivatePath:     priv,
		PublicPath:      priv + ".pub",
		PrivateOnDisk:   lexists(priv),
		PublicOnDisk:    lexists(priv + ".pub"),
		Hosts:           aliases,
		Status:          query.NoKey,
	}
	if fp, rec, ok := s.record(ident); ok {
		row.Recorded = true
		row.Fingerprint = fp
		row.Deployments = rec.Deployments
		row.Created = deref(rec.Created)
		row.ExpiresOn = deref(rec.ExpiresOn)
		row.Status = query.NeedsRedeploy
		if !rec.NeedsRedeploy() {
			row.Status = query.Deployed
		}
	}
	return row, nil
}

// record finds the inventory entry for an identity path. The inventory is keyed
// by fingerprint, so this is a scan; iteration order is randomized, so ties are
// broken by fingerprint to keep output stable rather than alternating between
// two records left at the same path.
func (s *Service) record(ident string) (string, inventory.KeyRecord, bool) {
	var fps []string
	for fp, rec := range s.inv.Keys {
		if rec.Path == ident {
			fps = append(fps, fp)
		}
	}
	if len(fps) == 0 {
		return "", inventory.KeyRecord{}, false
	}
	sort.Strings(fps)
	return fps[0], s.inv.Keys[fps[0]], true
}

func matches(selector string, r Row) bool {
	if selector == "" || selector == r.Ref.Profile ||
		selector == r.Ref.KeyName || selector == r.Ref.String() {
		return true
	}
	for _, alias := range r.Hosts {
		if alias == selector {
			return true
		}
	}
	return false
}

// lexists reports whether path exists without following a final symlink.
func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
