// Package keysvc is the key-centric read layer: for every key the manifest owns,
// what is on disk for it, which hosts wire it, and where it is deployed. The
// query package answers the same questions host-first (list/view); this one is
// key-first, because a key can now outlive - or precede - any host that uses it.
//
// It reports facts, not judgements: whether a file is there, whether a record
// covers it, which hosts name it. Deciding that some combination of those facts
// means a key is "dangling" belongs to one package so every command agrees, and
// that package is keyaudit, which reads these rows.
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
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/services/query"
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
	PrivateMode     os.FileMode // zero when the file is absent
	PublicMode      os.FileMode
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

// Detail is a Row plus what only reading the public key can answer.
type Detail struct {
	Row
	// DiskFingerprint is fingerprinted from the .pub actually on disk, which can
	// disagree with the recorded one after a key was regenerated outside sshmgr.
	// Empty when there is no .pub to read.
	DiskFingerprint string
	// FingerprintErr explains an unreadable or malformed .pub, rather than
	// letting it show as a blank fingerprint.
	FingerprintErr string
}

// Mismatched reports whether the key on disk is a different key from the one the
// inventory recorded - the state where deployments and expiry describe a key
// that no longer exists.
func (d Detail) Mismatched() bool {
	return d.Fingerprint != "" && d.DiskFingerprint != "" && d.Fingerprint != d.DiskFingerprint
}

// Detail returns one key's row plus the fingerprint of its public key on disk.
// Only the public half is ever read.
func (s *Service) Detail(ref manifest.KeyRef) (Detail, error) {
	row, err := s.row(ref)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Row: row}
	if row.PublicOnDisk {
		fp, err := keystore.New().Fingerprint(row.PublicPath)
		if err != nil {
			d.FingerprintErr = err.Error()
		} else {
			d.DiskFingerprint = fp
		}
	}
	return d, nil
}

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
	privMode, privOK := lmode(priv)
	pubMode, pubOK := lmode(priv + ".pub")
	row := Row{
		Ref:             ref,
		Type:            s.m.KeyTypeFor(ref),
		RotateAfterDays: s.m.RotateAfterDaysFor(ref),
		Declared:        declared,
		IdentityFile:    ident,
		PrivatePath:     priv,
		PublicPath:      priv + ".pub",
		PrivateOnDisk:   privOK,
		PublicOnDisk:    pubOK,
		PrivateMode:     privMode,
		PublicMode:      pubMode,
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

// lmode returns a path's permission bits without following a final symlink, and
// whether it exists at all.
func lmode(path string) (os.FileMode, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, false
	}
	return fi.Mode().Perm(), true
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
