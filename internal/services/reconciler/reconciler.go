// Package reconciler rebuilds the ~/.ssh tree from the manifest. Idempotent and
// non-destructive (ported from services/reconciler.py): it mints only missing keys
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

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/log"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
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
	for _, rk := range existing {
		res.ExistingKeys = append(res.ExistingKeys, rk.KeyName)
	}

	if dryRun {
		for _, rk := range toMint {
			res.Minted = append(res.Minted, MintedKey{
				KeyName: rk.KeyName, Profile: rk.Profile,
				Fingerprint: "(new)", Path: r.privPath(rk.Profile, rk.KeyName),
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
	for _, rk := range toMint {
		mk, err := r.mintOne(rk, passphrase, false)
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
// empty), plus regenerate any whose name is in overwrite (destructive; the caller
// snapshots first). No render.
func (r *Reconciler) Mint(selector, passphrase string, overwrite map[string]bool) ([]MintedKey, error) {
	toMint, existing, err := r.planMint(selector)
	if err != nil {
		return nil, err
	}
	var minted []MintedKey
	for _, rk := range toMint {
		mk, err := r.mintOne(rk, passphrase, false)
		if err != nil {
			return nil, err
		}
		minted = append(minted, mk)
	}
	for _, rk := range existing {
		if overwrite[rk.KeyName] {
			mk, err := r.mintOne(rk, passphrase, true)
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

// ExistingKeys lists key names that already have a private key on disk, deduped
// and filtered to selector.
func (r *Reconciler) ExistingKeys(selector string) ([]string, error) {
	_, existing, err := r.planMint(selector)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(existing))
	for _, rk := range existing {
		out = append(out, rk.KeyName)
	}
	return out, nil
}

// planMint returns (keys-to-mint, keys-already-present), deduped by private path
// and filtered to selector (a profile name or host alias) when given.
func (r *Reconciler) planMint(selector string) (toMint, existing []manifest.ResolvedKey, err error) {
	rks, err := r.m.IterResolved()
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, rk := range rks {
		if selector != "" && selector != rk.Profile && selector != rk.Host.Alias {
			continue
		}
		priv := r.privPath(rk.Profile, rk.KeyName)
		if seen[priv] {
			continue
		}
		seen[priv] = true
		if fs.Exists(priv) {
			existing = append(existing, rk)
		} else {
			toMint = append(toMint, rk)
		}
	}
	return toMint, existing, nil
}

func (r *Reconciler) ensureTree() error {
	ssh := r.p.SSHDir
	if err := fs.EnsureDir(ssh, perms.DirMode); err != nil {
		return err
	}
	if err := fs.EnsureDir(filepath.Join(ssh, "profiles"), perms.DirMode); err != nil {
		return err
	}
	for _, pname := range r.m.NonEmptyProfiles() {
		if err := fs.EnsureDir(filepath.Join(ssh, "profiles", pname), perms.DirMode); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) mintOne(rk manifest.ResolvedKey, passphrase string, overwrite bool) (MintedKey, error) {
	priv := r.privPath(rk.Profile, rk.KeyName)
	if err := fs.EnsureDir(filepath.Dir(priv), perms.DirMode); err != nil {
		return MintedKey{}, err
	}
	comment := fmt.Sprintf("%s/%s %s", rk.Profile, rk.Host.Alias, inventory.Today())
	gen, err := r.ks.Generate(priv, r.m.Defaults.KeyType, comment, passphrase, overwrite)
	if err != nil {
		return MintedKey{}, err
	}
	created := inventory.Today()
	ident := r.m.IdentityFile(rk.Profile, rk.KeyName)
	// Drop any stale inventory entry at this path (an old fingerprint left behind
	// when the previous key was deleted) so we never orphan it.
	for fp, rec := range r.inv.Keys {
		if rec.Path == ident && fp != gen.Fingerprint {
			delete(r.inv.Keys, fp)
		}
	}
	exp, _ := inventory.ComputeExpiry(created, r.m.Defaults.RotateAfterDays)
	r.inv.Record(gen.Fingerprint, inventory.KeyRecord{
		Profile:         rk.Profile,
		Path:            ident,
		Type:            r.m.Defaults.KeyType,
		Comment:         &comment,
		Created:         &created,
		RotateAfterDays: r.m.Defaults.RotateAfterDays,
		ExpiresOn:       &exp,
		Deployments:     nil, // empty == needs-redeploy
	})
	log.Audit(r.p.AuditLog(), "keygen",
		log.Field{Key: "key", Value: rk.KeyName},
		log.Field{Key: "fingerprint", Value: gen.Fingerprint},
		log.Field{Key: "profile", Value: rk.Profile})
	return MintedKey{KeyName: rk.KeyName, Profile: rk.Profile, Fingerprint: gen.Fingerprint, Path: priv}, nil
}

func (r *Reconciler) fixPerms() int {
	count := 0
	for _, mp := range perms.IterManagedPaths(r.p.SSHDir) {
		_ = perms.SetPerms(mp.Path, mp.Mode)
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
