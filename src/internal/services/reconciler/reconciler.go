// Package reconciler rebuilds the ~/.ssh tree from the manifest. Idempotent and
// non-destructive: it mints only missing keys
// - flagged needs-redeploy, never pretending a regenerated key is the lost
// original - re-renders config through the one renderer, fixes perms, and reports
// ssh -G validation. The snapshot/temp-residue sweep is the Facade's mutation
// guard, upstream of this, so it is not duplicated here.
package reconciler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/opstore"
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
	// Fallback names the software type minted when the hardware *-sk type the
	// manifest asks for had no security key to answer; "" otherwise.
	Fallback string `json:",omitempty"`
}

// ReconcileResult summarizes a reconcile run.
type ReconcileResult struct {
	DryRun           bool
	Minted           []MintedKey
	ExistingKeys     []string
	Recorded         []string // keys on disk that had no inventory record, now recorded
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
		if m.Fallback != "" {
			lines = append(lines, fmt.Sprintf("    no security key answered: this is a software %s key, not a hardware one; "+
				"insert the key and run `sshmgr rotate %s` to replace it", m.Fallback, m.KeyName))
		}
	}
	if len(r.Minted) == 0 {
		lines = append(lines, fmt.Sprintf("  keys: all %d present (none minted)", len(r.ExistingKeys)))
	}
	for _, name := range r.Recorded {
		lines = append(lines, fmt.Sprintf("  record %s: %s  (on disk, had no inventory record)", verb, name))
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
		if r.PermsFixed == 0 {
			lines = append(lines, "  perms: ok")
		} else {
			lines = append(lines, fmt.Sprintf("  perms fixed on %d paths", r.PermsFixed))
		}
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
	op  *opstore.Client // for profiles whose key_store is 1password
	cfg *configsvc.Service
}

// New builds a Reconciler. emitUseKeychain matches the platform (macOS only), as
// elsewhere.
func New(p paths.Paths, m *manifest.Manifest, inv *inventory.Inventory, emitUseKeychain bool) *Reconciler {
	return &Reconciler{
		p: p, m: m, inv: inv, ks: keystore.New(), op: opstore.New(),
		cfg: configsvc.New(p.SSHDir, m, emitUseKeychain),
	}
}

func (r *Reconciler) privPath(profile, keyName string) string {
	return r.m.KeyPath(r.p.SSHDir, manifest.KeyRef{Profile: profile, KeyName: keyName})
}

// present reports whether a key's on-disk part exists: the private key for a
// key on disk, the public key for one kept in 1Password.
func (r *Reconciler) present(ref manifest.KeyRef) bool {
	priv := r.privPath(ref.Profile, ref.KeyName)
	if r.m.Profiles[ref.Profile].InOnePassword() {
		return fs.Exists(priv + ".pub")
	}
	return fs.Exists(priv)
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
		for _, pk := range r.unrecorded(existing) {
			res.Recorded = append(res.Recorded, pk.Ref.KeyName)
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
	for _, pk := range r.unrecorded(existing) {
		if r.recordExisting(pk) {
			res.Recorded = append(res.Recorded, pk.Ref.KeyName)
		}
	}
	var mintErr error
	for _, pk := range toMint {
		mk, err := r.mintOne(pk, passphrase, false)
		if err != nil {
			mintErr = err
			break
		}
		res.Minted = append(res.Minted, mk)
	}
	if err := r.saveRecords(len(res.Minted)+len(res.Recorded) > 0, mintErr); err != nil {
		return nil, err
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
	var mintErr error
	for _, pk := range toMint {
		mk, err := r.mintOne(pk, passphrase, false)
		if err != nil {
			mintErr = err
			break
		}
		minted = append(minted, mk)
	}
	for _, pk := range existing {
		if mintErr != nil {
			break
		}
		if overwrite[pk.Ref] {
			mk, err := r.mintOne(pk, passphrase, true)
			if err != nil {
				mintErr = err
				break
			}
			minted = append(minted, mk)
		}
	}
	if len(minted) > 0 {
		r.fixPerms()
	}
	if err := r.saveRecords(len(minted) > 0, mintErr); err != nil {
		return nil, err
	}
	return minted, nil
}

// saveRecords persists the inventory when a run changed it, and then returns
// the run's own error. A key minted before a later one failed is already on
// disk, so its record has to be saved too: returning before the save left it
// unrecorded, and since every later run sees it as existing rather than
// missing, nothing would ever record it.
func (r *Reconciler) saveRecords(changed bool, runErr error) error {
	if changed {
		if err := r.inv.Save(r.p.Inventory()); err != nil {
			return errors.Join(runErr, err)
		}
	}
	return runErr
}

// unrecorded returns the keys present on disk that no inventory record covers.
// Coverage is by path, as `key list` and doctor judge it.
func (r *Reconciler) unrecorded(existing []plannedKey) []plannedKey {
	var out []plannedKey
	for _, pk := range existing {
		ident := r.m.IdentityFile(pk.Ref.Profile, pk.Ref.KeyName)
		covered := false
		for _, rec := range r.inv.Keys {
			if rec.Path == ident {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, pk)
		}
	}
	return out
}

// recordExisting records a key that is on disk with no inventory record - left
// by a run that failed after minting it, or by an inventory that was lost - so
// expiry and rotation stop being blind to it. It reports whether it recorded
// anything.
//
// The type and rotation interval are the ones the manifest gives this key.
// Created is the file's modification time, the closest thing to a mint date
// left; today would push the expiry out by however old the key already is. No
// deployments are claimed, because none are known: the next deploy records them.
func (r *Reconciler) recordExisting(pk plannedKey) bool {
	ref := pk.Ref
	priv := r.privPath(ref.Profile, ref.KeyName)
	src := priv + ".pub" // readable without the passphrase
	if !fs.Exists(src) {
		src = priv
	}
	fp, err := r.ks.Fingerprint(src)
	if err != nil {
		return false // unreadable: key list and doctor keep reporting it
	}
	if _, taken := r.inv.Keys[fp]; taken {
		return false // recorded under another path; that record is not ours to move
	}
	keyType := r.m.KeyTypeFor(ref)
	if r.m.Profiles[ref.Profile].InOnePassword() {
		keyType = "ed25519" // what 1Password generates, as mintOne records it
	}
	created := inventory.Today()
	if st, err := os.Stat(src); err == nil {
		created = st.ModTime().Format(time.DateOnly)
	}
	rotate := r.m.RotateAfterDaysFor(ref)
	exp, _ := inventory.ComputeExpiry(created, rotate)
	r.inv.Record(fp, inventory.KeyRecord{
		Profile:         ref.Profile,
		Path:            r.m.IdentityFile(ref.Profile, ref.KeyName),
		Type:            keyType,
		Created:         &created,
		RotateAfterDays: rotate,
		ExpiresOn:       &exp,
	})
	log.Audit(r.p.AuditLog(), "reconcile.record",
		log.Field{Key: "key", Value: ref.KeyName},
		log.Field{Key: "fingerprint", Value: fp},
		log.Field{Key: "profile", Value: ref.Profile})
	return true
}

// MintRef mints exactly one key, by reference. It returns nil when the private
// key is already on disk: a command that adds a key must never regenerate an
// identity that exists, since the replaced key is what remote targets trust.
func (r *Reconciler) MintRef(ref manifest.KeyRef, passphrase string) (*MintedKey, error) {
	if r.present(ref) {
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
		priv := r.privPath(ref.Profile, ref.KeyName)
		if r.present(ref) {
			existing = append(existing, pk)
			continue
		}
		if elsewhere := r.misplaced(ref, priv); elsewhere != "" {
			return nil, nil, fmt.Errorf("key %s is not at %s but at %s - refusing to mint a "+
				"replacement for a key that still exists; move it back, or set profile %q's "+
				"category to match where it is", ref, priv, elsewhere, ref.Profile)
		}
		toMint = append(toMint, pk)
	}
	return toMint, existing, nil
}

// misplaced returns where a key the manifest expects at priv actually sits, if
// it is in the other layout: flat when the manifest says categorized, or under
// a category the manifest does not name. Minting there would leave two keys
// for one identity, the old one still deployed and the new one not. "" when
// the key is nowhere else.
func (r *Reconciler) misplaced(ref manifest.KeyRef, priv string) string {
	name, want := ref.KeyName, priv
	if r.m.Profiles[ref.Profile].InOnePassword() {
		name, want = name+".pub", priv+".pub" // only the public half is ever on disk
	}
	for _, p := range manifest.GlobProfileTree(r.p.SSHDir, name) {
		if p != want && filepath.Base(filepath.Dir(p)) == ref.Profile {
			return p
		}
	}
	return ""
}

// mintInOnePassword creates the key as an SSH Key item titled with the key name
// in the profile's vault, and writes only its public half to pub. An item that
// already has that title is reused rather than duplicated: a .pub deleted from
// disk is restored from the vault, never replaced by a second key.
func (r *Reconciler) mintInOnePassword(ref manifest.KeyRef, pub string, overwrite bool) (keystore.GenResult, error) {
	if overwrite {
		return keystore.GenResult{}, fmt.Errorf("key %s is kept in 1Password; replace it with "+
			"`sshmgr rotate %s`, which stages, deploys and verifies the new key first", ref, ref)
	}
	vault := r.m.Profiles[ref.Profile].OPVault
	it, err := r.op.Get(vault, ref.KeyName)
	switch {
	case err == nil:
	case errors.Is(err, opstore.ErrNotFound):
		if it, err = r.op.Create(vault, ref.KeyName); err != nil {
			return keystore.GenResult{}, err
		}
	default:
		return keystore.GenResult{}, err
	}
	if it.PublicKey == "" {
		return keystore.GenResult{}, fmt.Errorf("1Password item %q in vault %q has no public key - "+
			"is it an SSH Key item?", ref.KeyName, vault)
	}
	if err := fs.WriteTextAtomic(pub, it.PublicKey+"\n", perms.PublicKeyMode); err != nil {
		return keystore.GenResult{}, err
	}
	fp, err := r.ks.Fingerprint(pub)
	if err != nil {
		return keystore.GenResult{}, err
	}
	return keystore.GenResult{Fingerprint: fp}, nil
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
		if err := fs.EnsureDir(r.m.ProfileDir(ssh, pname), perms.DirMode); err != nil {
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
	comment := manifest.KeyComment(r.m, ref, subject, inventory.Today())
	// An overwrite moves the key it replaces into old/ (keystore's
	// archivePredecessor), so its record has to follow it there.
	archived := overwrite && fs.Exists(priv)
	var gen keystore.GenResult
	var err error
	if r.m.Profiles[ref.Profile].InOnePassword() {
		gen, err = r.mintInOnePassword(ref, priv+".pub", overwrite)
		keyType = "ed25519" // what 1Password generates
	} else {
		gen, err = r.ks.Generate(priv, keyType, comment, passphrase, overwrite)
	}
	if err != nil {
		return MintedKey{}, err
	}
	fallback := ""
	if gen.Created && gen.Type != "" {
		// Record the key that exists: a hardware type with no device answering
		// was minted as its software equivalent.
		if gen.Fallback {
			fallback = gen.Type
		}
		keyType, comment = gen.Type, gen.Comment
	}
	created := inventory.Today()
	ident := r.m.IdentityFile(ref.Profile, ref.KeyName)
	if archived {
		r.archiveRecord(ref, priv, gen.Fingerprint)
	}
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
	return MintedKey{KeyName: ref.KeyName, Profile: ref.Profile, Fingerprint: gen.Fingerprint, Path: priv, Fallback: fallback}, nil
}

// archiveRecord moves the record of the key an overwrite just displaced from
// the canonical path to old/, where the key itself now is, the way a rotation
// does (Rotator.updateInventory). Deleting it instead, as the stale-entry prune
// used to, left a later `rollback` restoring a key with no record: the active
// key unrecorded, its deployments and expiry gone.
func (r *Reconciler) archiveRecord(ref manifest.KeyRef, priv, newFP string) {
	ident := r.m.IdentityFile(ref.Profile, ref.KeyName)
	oldIdent := r.m.IdentityFile(ref.Profile, "old/"+ref.KeyName)
	outgoing := ""
	oldPub := filepath.Join(filepath.Dir(priv), "old", filepath.Base(priv)) + ".pub"
	if fp, err := r.ks.Fingerprint(oldPub); err == nil {
		outgoing = fp
	}
	// old/ keeps one predecessor, so any other record there is for the key the
	// archive just replaced on disk.
	for fp, rec := range r.inv.Keys {
		if rec.Path == oldIdent && fp != outgoing {
			delete(r.inv.Keys, fp)
		}
	}
	if rec, ok := r.inv.Keys[outgoing]; ok && outgoing != "" {
		rec.Path = oldIdent
		r.inv.Keys[outgoing] = rec
		return
	}
	// The archived .pub could not be read (a half pair, say), so the outgoing
	// key is whichever record still claims the canonical path. Rotator falls
	// back the same way.
	if outgoing == "" {
		for fp, rec := range r.inv.Keys {
			if rec.Path == ident && fp != newFP {
				rec.Path = oldIdent
				r.inv.Keys[fp] = rec
			}
		}
	}
}

// fixPerms tightens both the ~/.ssh tree and the config home. Reconcile used to
// cover only ~/.ssh while `doctor --fix` covered both, so reconciling left the
// manifest and providers.json at whatever mode the umask produced and a following
// doctor run reported perm issues it had just been asked to prevent.
//
// It returns how many paths actually changed mode. It used to count every
// path it visited, so a tree that was already correct reported "perms fixed
// on 53 paths" on every run - indistinguishable from real drift.
func (r *Reconciler) fixPerms() int {
	count := 0
	fix := func(path string, mode os.FileMode) {
		if perms.PermsOK(path, mode) {
			return
		}
		if perms.SetPerms(path, mode) == nil {
			count++
		}
	}
	for _, mp := range perms.IterManagedPaths(r.p.SSHDir) {
		fix(mp.Path, mp.Mode)
	}
	for _, sp := range homeperms.SecretPerms(r.p) {
		if !fs.Exists(sp.Path) {
			continue
		}
		fix(sp.Path, sp.Mode)
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
