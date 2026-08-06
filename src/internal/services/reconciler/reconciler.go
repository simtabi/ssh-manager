// Package reconciler rebuilds the ~/.ssh tree from the manifest. Idempotent and
// non-destructive: it mints only missing keys
// - flagged needs-redeploy, never pretending a regenerated key is the lost
// original - re-renders config through the one renderer, fixes perms, and reports
// ssh -G validation. The snapshot/temp-residue sweep is the Facade's mutation
// guard, upstream of this, so it is not duplicated here.
package reconciler

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/homeperms"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// MintedKey is one key generated during reconcile/keygen.
type MintedKey struct {
	KeyName     string
	Profile     string
	Fingerprint string
	Path        string
}

// ReconcileResult summarizes a reconcile run.
type ReconcileResult struct {
	DryRun           bool
	Minted           []MintedKey
	ExistingKeys     []string
	Config           *configsvc.WriteResult
	PermsFixed       int
	Snapshot         *string
	ValidationErrors map[string]string
	Pinned           map[string]int
}

// Format renders the human-readable summary (mirrors ReconcileResult.format).
func (r *ReconcileResult) Format() string {
	verb := "did"
	applied := "applied"
	if r.DryRun {
		verb = "would"
		applied = "dry-run"
	}
	lines := []string{fmt.Sprintf("reconcile (%s):", applied)}
	if r.Snapshot != nil {
		lines = append(lines, "  snapshot: "+*r.Snapshot)
	}
	for _, m := range r.Minted {
		lines = append(lines, fmt.Sprintf("  mint %s: %s  %s  (needs-redeploy)", verb, m.KeyName, m.Fingerprint))
	}
	if len(r.Minted) == 0 {
		lines = append(lines, fmt.Sprintf("  keys: all %d present (none minted)", len(r.ExistingKeys)))
	}
	if r.Config != nil {
		if len(r.Config.Written) > 0 {
			lines = append(lines, fmt.Sprintf("  config %s write: %s", verb, strings.Join(r.Config.Written, ", ")))
		}
		if len(r.Config.Pruned) > 0 {
			lines = append(lines, fmt.Sprintf("  config %s prune: %s", verb, strings.Join(r.Config.Pruned, ", ")))
		}
		if len(r.Config.Written) == 0 && len(r.Config.Pruned) == 0 {
			lines = append(lines, "  config: already in sync")
		}
	}
	if !r.DryRun {
		lines = append(lines, fmt.Sprintf("  perms fixed on %d paths", r.PermsFixed))
	}
	if len(r.Pinned) > 0 {
		keys := make([]string, 0, len(r.Pinned))
		for p := range r.Pinned {
			keys = append(keys, p)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, p := range keys {
			parts[i] = fmt.Sprintf("%s=%d", p, r.Pinned[p])
		}
		lines = append(lines, "  host keys auto-pinned: "+strings.Join(parts, ", "))
	}
	for _, alias := range sortedKeys(r.ValidationErrors) {
		lines = append(lines, fmt.Sprintf("  ssh -G %s: %s", alias, r.ValidationErrors[alias]))
	}
	return strings.Join(lines, "\n")
}

// Reconciler reconciles the manifest into ~/.ssh.
type Reconciler struct {
	p   paths.Paths
	m   *manifest.Manifest
	inv *inventory.Inventory
	ks  *keystore.KeyStore
	cfg *configsvc.Service
}

// New builds a Reconciler. emitUseKeychain matches the platform (macOS only), as
// elsewhere.
func New(p paths.Paths, m *manifest.Manifest, inv *inventory.Inventory, emitUseKeychain bool) *Reconciler {
	return &Reconciler{
		p: p, m: m, inv: inv, ks: keystore.New(),
		cfg: configsvc.New(p.SSHDir, m, emitUseKeychain),
	}
}

func (r *Reconciler) privPath(profile, keyName string) string {
	return filepath.Join(r.p.SSHDir, "profiles", profile, keyName)
}

// Reconcile rebuilds the tree (mints missing keys, renders config, fixes perms,
// validates). With dryRun it only plans key work and previews the config write.
func (r *Reconciler) Reconcile(dryRun bool, passphrase string) (*ReconcileResult, error) {
	res := &ReconcileResult{DryRun: dryRun}

	toMint, existing, err := r.planMint("")
	if err != nil {
		return nil, err
	}
	for _, pk := range existing {
		res.ExistingKeys = append(res.ExistingKeys, pk.Ref.KeyName)
	}

	if dryRun {
		for _, pk := range toMint {
			res.Minted = append(res.Minted, MintedKey{
				KeyName: pk.Ref.KeyName, Profile: pk.Ref.Profile,
				Fingerprint: "(new)", Path: r.privPath(pk.Ref.Profile, pk.Ref.KeyName),
			})
		}
		c, err := r.cfg.Write(true)
		if err != nil {
			return nil, err
		}
		res.Config = c
		return res, nil
	}

	if err := r.ensureTree(); err != nil {
		return nil, err
	}
	for _, pk := range toMint {
		mk, err := r.mintOne(pk, passphrase, false)
		if err != nil {
			return nil, err
		}
		res.Minted = append(res.Minted, mk)
	}
	if len(toMint) > 0 {
		if err := r.inv.Save(r.p.Inventory()); err != nil {
			return nil, err
		}
	}
	c, err := r.cfg.Write(false)
	if err != nil {
		return nil, err
	}
	res.Config = c
	res.PermsFixed = r.fixPerms()
	if chk, err := r.cfg.Check(true); err == nil {
		res.ValidationErrors = chk.SSHErrors
	}
	log.Audit(r.p.AuditLog(), "reconcile",
		log.Field{Key: "minted", Value: len(res.Minted)},
		log.Field{Key: "config_written", Value: len(c.Written)})
	return res, nil
}

// Mint is the targeted keygen primitive: mint missing keys for selector (all if
// empty), plus regenerate any key in overwrite (destructive; the caller
// snapshots first). No render.
//
// overwrite is keyed by KeyRef, not by name. Key names are unique per profile,
// not globally - one person under two orgs uses the same file name in both - so
// a name-keyed set meant confirming "overwrite imani_github-ed25519" regenerated
// it in every profile that had one, destroying identities the user was never
// asked about.
func (r *Reconciler) Mint(selector, passphrase string, overwrite map[manifest.KeyRef]bool) ([]MintedKey, error) {
	toMint, existing, err := r.planMint(selector)
	if err != nil {
		return nil, err
	}
	var minted []MintedKey
	for _, pk := range toMint {
		mk, err := r.mintOne(pk, passphrase, false)
		if err != nil {
			return nil, err
		}
		minted = append(minted, mk)
	}
	for _, pk := range existing {
		if overwrite[pk.Ref] {
			mk, err := r.mintOne(pk, passphrase, true)
			if err != nil {
				return nil, err
			}
			minted = append(minted, mk)
		}
	}
	if len(minted) > 0 {
		if err := r.inv.Save(r.p.Inventory()); err != nil {
			return nil, err
		}
		r.fixPerms()
	}
	return minted, nil
}

// MintRef mints exactly one key, by reference. It returns nil when the private
// key is already on disk: a command that adds a key must never regenerate an
// identity that exists, since the replaced key is what remote targets trust.
func (r *Reconciler) MintRef(ref manifest.KeyRef, passphrase string) (*MintedKey, error) {
	if fs.Exists(r.privPath(ref.Profile, ref.KeyName)) {
		return nil, nil
	}
	hosts, err := r.m.HostsForKey(ref)
	if err != nil {
		return nil, err
	}
	if err := r.ensureTree(); err != nil {
		return nil, err
	}
	mk, err := r.mintOne(plannedKey{Ref: ref, Hosts: hosts}, passphrase, false)
	if err != nil {
		return nil, err
	}
	if err := r.inv.Save(r.p.Inventory()); err != nil {
		return nil, err
	}
	r.fixPerms()
	return &mk, nil
}

// ExistingKeys lists the keys that already have a private key on disk, filtered
// to selector. Refs, not names: the caller prompts per key before overwriting
// one, and two profiles can hold the same name.
func (r *Reconciler) ExistingKeys(selector string) ([]manifest.KeyRef, error) {
	_, existing, err := r.planMint(selector)
	if err != nil {
		return nil, err
	}
	out := make([]manifest.KeyRef, 0, len(existing))
	for _, pk := range existing {
		out = append(out, pk.Ref)
	}
	return out, nil
}

// plannedKey is one key the reconciler may mint: the key itself plus the hosts
// that reference it - none for a key its profile declares that no host uses yet,
// which still has to be minted so the declaration means something.
type plannedKey struct {
	Ref   manifest.KeyRef
	Hosts []manifest.Host
}

// planMint returns (keys-to-mint, keys-already-present), filtered to selector (a
// profile name or a host alias) when given. It walks KeyRefs rather than
// IterResolved so a declared-but-unwired key is planned too; KeyRefs is already
// deduplicated per profile+name, so hosts sharing a key yield one plan entry.
func (r *Reconciler) planMint(selector string) (toMint, existing []plannedKey, err error) {
	refs, err := r.m.KeyRefs()
	if err != nil {
		return nil, nil, err
	}
	for _, ref := range refs {
		hosts, err := r.m.HostsForKey(ref)
		if err != nil {
			return nil, nil, err
		}
		if !planMatches(selector, ref, hosts) {
			continue
		}
		pk := plannedKey{Ref: ref, Hosts: hosts}
		if fs.Exists(r.privPath(ref.Profile, ref.KeyName)) {
			existing = append(existing, pk)
		} else {
			toMint = append(toMint, pk)
		}
	}
	return toMint, existing, nil
}

// planMatches reports whether a key is in scope for selector: everything when
// empty, else the profile that owns it, the key itself (by name or in the
// "profile/key" form), or any host alias that uses it.
//
// The key forms matter because `keygen` is the one command whose whole purpose
// is a single key, and it was the only selector in the tool that would not
// accept one - `sshmgr keygen work/work_gh-ed25519` was an unknown target.
func planMatches(selector string, ref manifest.KeyRef, hosts []manifest.Host) bool {
	if selector == "" || selector == ref.Profile ||
		selector == ref.KeyName || selector == ref.String() {
		return true
	}
	for _, h := range hosts {
		if h.Alias == selector {
			return true
		}
	}
	return false
}

// ensureTree creates ~/.ssh, profiles/, and a directory for every profile that
// owns a key - hosts or not, since a profile can now declare a key without one.
func (r *Reconciler) ensureTree() error {
	ssh := r.p.SSHDir
	if err := fs.EnsureDir(ssh, perms.DirMode); err != nil {
		return err
	}
	if err := fs.EnsureDir(filepath.Join(ssh, "profiles"), perms.DirMode); err != nil {
		return err
	}
	wanted := map[string]bool{}
	var order []string
	remember := func(pname string) {
		if !wanted[pname] {
			wanted[pname] = true
			order = append(order, pname)
		}
	}
	for _, pname := range r.m.NonEmptyProfiles() {
		remember(pname)
	}
	refs, err := r.m.KeyRefs()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		remember(ref.Profile)
	}
	for _, pname := range order {
		if err := fs.EnsureDir(filepath.Join(ssh, "profiles", pname), perms.DirMode); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) mintOne(pk plannedKey, passphrase string, overwrite bool) (MintedKey, error) {
	ref := pk.Ref
	priv := r.privPath(ref.Profile, ref.KeyName)
	if err := fs.EnsureDir(filepath.Dir(priv), perms.DirMode); err != nil {
		return MintedKey{}, err
	}
	// The comment identifies the key in ssh-keygen -l output. A wired key names
	// the host it serves; an unwired one has none, so it names itself.
	subject := ref.KeyName
	if len(pk.Hosts) > 0 {
		subject = pk.Hosts[0].Alias
	}
	keyType := r.m.KeyTypeFor(ref)
	comment := fmt.Sprintf("%s/%s %s", ref.Profile, subject, inventory.Today())
	gen, err := r.ks.Generate(priv, keyType, comment, passphrase, overwrite)
	if err != nil {
		return MintedKey{}, err
	}
	created := inventory.Today()
	ident := r.m.IdentityFile(ref.Profile, ref.KeyName)
	// Drop any stale inventory entry at this path (an old fingerprint left behind
	// when the previous key was deleted) so we never orphan it.
	for fp, rec := range r.inv.Keys {
		if rec.Path == ident && fp != gen.Fingerprint {
			delete(r.inv.Keys, fp)
		}
	}
	rotate := r.m.RotateAfterDaysFor(ref)
	exp, _ := inventory.ComputeExpiry(created, rotate)
	r.inv.Record(gen.Fingerprint, inventory.KeyRecord{
		Profile:         ref.Profile,
		Path:            ident,
		Type:            keyType,
		Comment:         &comment,
		Created:         &created,
		RotateAfterDays: rotate,
		ExpiresOn:       &exp,
		Deployments:     nil, // empty == needs-redeploy
	})
	log.Audit(r.p.AuditLog(), "keygen",
		log.Field{Key: "key", Value: ref.KeyName},
		log.Field{Key: "fingerprint", Value: gen.Fingerprint},
		log.Field{Key: "profile", Value: ref.Profile})
	return MintedKey{KeyName: ref.KeyName, Profile: ref.Profile, Fingerprint: gen.Fingerprint, Path: priv}, nil
}

// fixPerms tightens both the ~/.ssh tree and the config home. Reconcile used to
// cover only ~/.ssh while `doctor --fix` covered both, so reconciling left the
// manifest and providers.json at whatever mode the umask produced and a following
// doctor run reported perm issues it had just been asked to prevent.
func (r *Reconciler) fixPerms() int {
	count := 0
	for _, mp := range perms.IterManagedPaths(r.p.SSHDir) {
		_ = perms.SetPerms(mp.Path, mp.Mode)
		count++
	}
	for _, sp := range homeperms.SecretPerms(r.p) {
		if !fs.Exists(sp.Path) {
			continue
		}
		_ = perms.SetPerms(sp.Path, sp.Mode)
		count++
	}
	return count
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
