// Package rotator does zero-downtime, staged, single-old-archive key rotation,
// ported from services/rotator.py. rotate stages a replacement, deploys it to
// every target (the current key stays active), verifies, and only then commits
// (archive current under /old/, promote staged, revoke old). On any pre-commit
// failure the staged key is discarded and the active key is untouched. rollback is
// the symmetric reverse move of the single /old/ key.
package rotator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/core/providers"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/log"
	"github.com/simtabi/ssh-manager/internal/util/netcheck"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// TargetResult is one target's rotation outcome.
type TargetResult struct {
	Alias    string
	Provider string
	Deployed bool
	Verified bool
	Revoked  bool
}

// RotateReport summarizes a rotate/rollback run.
type RotateReport struct {
	KeyName        string
	OldFingerprint string
	NewFingerprint string
	Committed      bool
	Message        string
	Targets        []TargetResult
}

// Format renders the rotation summary (mirrors RotateReport.format).
func (r RotateReport) Format() string {
	head := "rotation ABORTED"
	if r.Committed {
		head = "rotated"
	}
	lines := []string{head + ": " + r.KeyName}
	if r.OldFingerprint != "" {
		lines = append(lines, "  old: "+r.OldFingerprint)
	}
	if r.NewFingerprint != "" {
		lines = append(lines, "  new: "+r.NewFingerprint)
	}
	for _, t := range r.Targets {
		lines = append(lines, fmt.Sprintf("  %s (%s): deploy=%s verify=%s revoke=%s",
			t.Alias, t.Provider, okFail(t.Deployed), yesNo(t.Verified), revokeFlag(t.Revoked)))
	}
	if r.Message != "" {
		lines = append(lines, "  "+r.Message)
	}
	return strings.Join(lines, "\n")
}

func okFail(b bool) string {
	if b {
		return "ok"
	}
	return "FAIL"
}
func yesNo(b bool) string {
	if b {
		return "ok"
	}
	return "no"
}
func revokeFlag(b bool) string {
	if b {
		return "ok"
	}
	return "-"
}

// Rotator rotates keys.
type Rotator struct {
	p   paths.Paths
	m   *manifest.Manifest
	inv *inventory.Inventory
	ks  *keystore.KeyStore
}

// New builds a Rotator.
func New(p paths.Paths, m *manifest.Manifest, inv *inventory.Inventory) *Rotator {
	return &Rotator{p: p, m: m, inv: inv, ks: keystore.New()}
}

// profileAndHosts resolves a key selector to its owning profile and the hosts
// that use it. Hosts are scoped to that one profile: rotating touches files in a
// single profile directory, so pulling in a same-named key from another profile
// would deploy against hosts whose key was never rotated.
func (r *Rotator) profileAndHosts(selector string) (string, string, []manifest.Host, error) {
	ref, err := r.m.ResolveKeySelector(selector)
	if err != nil {
		return "", "", nil, err
	}
	hosts, err := r.m.HostsForKey(ref)
	if err != nil {
		return "", "", nil, err
	}
	if len(hosts) == 0 {
		return "", "", nil, fmt.Errorf("no host in the manifest uses key %q", ref)
	}
	return ref.Profile, ref.KeyName, hosts, nil
}

func (r *Rotator) dir(profile string) string {
	return filepath.Join(r.p.SSHDir, "profiles", profile)
}

func (r *Rotator) provider(h manifest.Host) providers.Provider {
	return providers.Resolve(deref(h.Provider), r.p.Providers())
}

func (r *Rotator) target(h manifest.Host, profile, pubPath, pubText, identPath string) providers.Target {
	return providers.Target{
		Alias: h.Alias, Hostname: h.Hostname, User: h.User, Port: h.Port,
		PubkeyPath: pubPath, PubkeyText: pubText, TokenEnv: deref(h.TokenEnv),
		IdentityPath: identPath, KnownHosts: filepath.Join(r.p.SSHDir, "known_hosts"),
	}
}

func (r *Rotator) unreachable(hosts []manifest.Host) []string {
	var msgs []string
	for _, h := range hosts {
		if r.provider(h).Category() != "server" {
			continue
		}
		st := netcheck.Check(h.Hostname, h.Port, h.RequiresVPN, deref(h.VPNName), deref(h.VPNURL), 4*time.Second, true)
		if !st.Reachable {
			msgs = append(msgs, st.Message())
		}
	}
	return msgs
}

// Rotate stages a fresh key, deploys+verifies it on every target, and commits only
// if all verified (or allowUnverified and all deployed). Mirrors Rotator.rotate.
func (r *Rotator) Rotate(selector string, allowUnverified bool, passphrase string) (RotateReport, error) {
	profile, keyName, hosts, err := r.profileAndHosts(selector)
	if err != nil {
		return RotateReport{}, err
	}
	pdir := r.dir(profile)
	curPriv := filepath.Join(pdir, keyName)
	curPub := curPriv + ".pub"
	if !exists(curPriv) {
		return RotateReport{}, fmt.Errorf("key not present: %s - run `sshmgr reconcile` first", curPriv)
	}
	report := RotateReport{KeyName: keyName}
	if fp, err := r.ks.Fingerprint(curPub); err == nil {
		report.OldFingerprint = fp
	}
	oldPubText := readFile(curPub)

	// 0. Preflight: every SSH target must answer before we stage/deploy.
	if msgs := r.unreachable(hosts); len(msgs) > 0 {
		report.Message = "cannot rotate - " + strings.Join(msgs, "; ")
		log.Audit(r.p.AuditLog(), "rotate.unreachable", log.Field{Key: "key", Value: keyName})
		return report, nil
	}

	// 1. Stage a fresh keypair (discard any crashed-rotation leftover).
	staging := filepath.Join(pdir, ".staging")
	_ = os.RemoveAll(staging)
	if err := fs.EnsureDir(staging, perms.DirMode); err != nil {
		return RotateReport{}, err
	}
	stagedPriv := filepath.Join(staging, keyName)
	stagedPub := stagedPriv + ".pub"
	comment := fmt.Sprintf("%s/%s %s", profile, hosts[0].Alias, inventory.Today())
	gen, err := r.ks.Generate(stagedPriv, r.m.Defaults.KeyType, comment, passphrase, false)
	if err != nil {
		return RotateReport{}, err
	}
	report.NewFingerprint = gen.Fingerprint

	// 2+3. Deploy the staged pubkey to every target, then verify login.
	stagedPubText := readFile(stagedPub)
	var results []TargetResult
	for _, h := range hosts {
		prov := r.provider(h)
		tr := TargetResult{Alias: h.Alias, Provider: prov.Name()}
		tgt := r.target(h, profile, stagedPub, stagedPubText, stagedPriv)
		out := prov.Deploy(tgt)
		tr.Deployed = out.Method == "manual" || out.Verified
		tr.Verified = prov.Verify(tgt)
		results = append(results, tr)
	}
	report.Targets = results

	ready := allTrue(results, func(t TargetResult) bool { return t.Verified }) ||
		(allowUnverified && allTrue(results, func(t TargetResult) bool { return t.Deployed }))
	if !ready {
		// Pull the staged pubkey back off every target it reached.
		for i, h := range hosts {
			if !results[i].Deployed {
				continue
			}
			tgt := r.target(h, profile, stagedPub, stagedPubText, "")
			_ = r.provider(h).Remove(tgt)
		}
		_ = os.RemoveAll(staging)
		report.Message = "verification failed on one or more targets - staged key discarded " +
			"(and pulled back from any target it reached), active key untouched. " +
			"(Use --allow-unverified to accept manual/web-panel targets.)"
		log.Audit(r.p.AuditLog(), "rotate.abort", log.Field{Key: "key", Value: keyName}, log.Field{Key: "old", Value: report.OldFingerprint})
		return report, nil
	}

	// 4. COMMIT.
	//
	// The canonical path is the only identity ssh will offer, so it has to hold a
	// working private key at every instant. This used to be four bare renames -
	// current pair out to old/, staged pair in - and any one of them failing left
	// the canonical path empty with the live key sitting in old/ or .staging/,
	// discovered the next time the user tried to push. Nothing put it back.
	//
	// Now the outgoing pair is preserved into old/ by hard link, so the canonical
	// path still points at it while the copy is made, and the staged pair is
	// renamed *over* the canonical path - which POSIX defines as atomic. A crash
	// between any two steps leaves a complete, working key behind, and a failure
	// puts back whatever had already moved.
	oldDir := filepath.Join(pdir, "old")
	if err := fs.EnsureDir(oldDir, perms.DirMode); err != nil {
		return RotateReport{}, fmt.Errorf("could not prepare the archive directory, so the rotation "+
			"was not committed (the active key is untouched): %w", err)
	}
	oldPrivSlot := filepath.Join(oldDir, keyName)
	if err := preservePair(curPriv, oldPrivSlot); err != nil {
		return RotateReport{}, fmt.Errorf("could not archive the outgoing key, so the rotation was "+
			"not committed (the active key is untouched): %w", err)
	}
	if err := os.Rename(stagedPriv, curPriv); err != nil {
		// The canonical pair never moved; drop the archive copy we just made so
		// old/ does not claim a predecessor that was never replaced.
		removePair(oldPrivSlot)
		return RotateReport{}, fmt.Errorf("could not move the new key into place, so the rotation "+
			"was not committed (the active key is untouched): %w", err)
	}
	if err := os.Rename(stagedPub, curPub); err != nil {
		// The private half already changed. Put the preserved one back so the
		// canonical pair matches itself again.
		if rerr := os.Rename(oldPrivSlot, curPriv); rerr != nil {
			return RotateReport{}, fmt.Errorf("the rotation failed midway AND could not be undone. "+
				"%s now holds the NEW private key while %s is the OLD public key, and the "+
				"previous private key is at %s. Restore by hand, or run `sshmgr rollback %s`: "+
				"%w (undo also failed: %v)", curPriv, curPub, oldPrivSlot, keyName, err, rerr)
		}
		removePair(oldPrivSlot)
		return RotateReport{}, fmt.Errorf("could not move the new public key into place, so the "+
			"rotation was undone and the previous key is active again: %w", err)
	}
	// Only now: before the swap the archive shared an inode with the live key, so
	// setting its mode would have set the live key's too.
	_ = perms.SetPerms(curPriv, perms.PrivateKeyMode)
	_ = perms.SetPerms(curPub, perms.PublicKeyMode)
	_ = perms.SetPerms(oldPrivSlot, perms.PrivateKeyMode)
	_ = perms.SetPerms(oldPrivSlot+".pub", perms.PublicKeyMode)
	_ = os.RemoveAll(staging)

	// Revoke the old public key from each target (best-effort).
	oldPub := oldPrivSlot + ".pub"
	for i := range hosts {
		tgt := r.target(hosts[i], profile, oldPub, oldPubText, "")
		results[i].Revoked = r.provider(hosts[i]).Remove(tgt)
	}
	report.Targets = results

	r.updateInventory(profile, keyName, report, results)
	report.Committed = true
	log.Audit(r.p.AuditLog(), "rotate", log.Field{Key: "key", Value: keyName},
		log.Field{Key: "old", Value: report.OldFingerprint}, log.Field{Key: "new", Value: report.NewFingerprint})
	return report, nil
}

func (r *Rotator) updateInventory(profile, keyName string, report RotateReport, results []TargetResult) {
	ident := r.m.IdentityFile(profile, keyName)
	oldIdent := fmt.Sprintf("~/.ssh/profiles/%s/old/%s", profile, keyName)
	// Drop any stale record still at the single /old/ slot (a prior predecessor).
	for fp, rec := range r.inv.Keys {
		if rec.Path == oldIdent && fp != report.OldFingerprint {
			delete(r.inv.Keys, fp)
		}
	}
	// Keep the outgoing record but mark it archived (path -> old/).
	if rec, ok := r.inv.Keys[report.OldFingerprint]; ok {
		rec.Path = oldIdent
		r.inv.Keys[report.OldFingerprint] = rec
	}
	created := inventory.Today()
	exp, _ := inventory.ComputeExpiry(created, r.m.Defaults.RotateAfterDays)
	comment := fmt.Sprintf("%s/%s %s", profile, keyName, created)
	r.inv.Record(report.NewFingerprint, inventory.KeyRecord{
		Profile: profile, Path: ident, Type: r.m.Defaults.KeyType,
		Comment: &comment, Created: &created, RotateAfterDays: r.m.Defaults.RotateAfterDays,
		ExpiresOn: &exp, Deployments: deployments(results, created),
	})
}

// Rollback restores the single /old/ predecessor (plain reverse move), re-deploys
// it, and revokes the rotated-in key. Mirrors Rotator.rollback.
func (r *Rotator) Rollback(selector string) (RotateReport, error) {
	profile, keyName, hosts, err := r.profileAndHosts(selector)
	if err != nil {
		return RotateReport{}, err
	}
	pdir := r.dir(profile)
	oldPriv := filepath.Join(pdir, "old", keyName)
	oldPub := oldPriv + ".pub"
	if !exists(oldPriv) {
		return RotateReport{}, fmt.Errorf("no /old/ predecessor to roll back to for %q", keyName)
	}
	curPriv := filepath.Join(pdir, keyName)
	curPub := curPriv + ".pub"

	report := RotateReport{KeyName: keyName}
	if exists(curPub) {
		if fp, err := r.ks.Fingerprint(curPub); err == nil {
			report.OldFingerprint = fp
		}
	}
	curPubText := readFile(curPub)
	if fp, err := r.ks.Fingerprint(oldPub); err == nil {
		report.NewFingerprint = fp
	}

	// Reverse move: predecessor -> canonical, replacing the rotated-in key.
	//
	// Nothing is removed first. This used to delete the canonical pair and then
	// move the predecessor in, so a failed rename left the canonical path empty
	// with the key it had just deleted gone for good - a rollback that locks you
	// out is worse than the rotation it was undoing. Rename over an existing file
	// is atomic, so the canonical path holds a complete private key throughout.
	if err := os.Rename(oldPriv, curPriv); err != nil {
		return RotateReport{}, fmt.Errorf("could not restore the previous private key, so nothing "+
			"was rolled back (the rotated-in key is still active): %w", err)
	}
	if err := os.Rename(oldPub, curPub); err != nil {
		// The private half is restored and working; only the .pub is stale. It is
		// derivable from the private key, so derive it rather than leave a pair
		// that does not match itself.
		if !r.rederivePub(curPriv, curPub) {
			return RotateReport{}, fmt.Errorf("the previous private key was restored to %s and is "+
				"active, but its public key could not be put back: %s still holds the rotated-in "+
				"public key. Re-derive it with `ssh-keygen -y -f %s > %s`: %w",
				curPriv, curPub, curPriv, curPub, err)
		}
		log.Audit(r.p.AuditLog(), "rollback.pub-rederived", log.Field{Key: "key", Value: keyName})
	}
	_ = perms.SetPerms(curPriv, perms.PrivateKeyMode)
	_ = perms.SetPerms(curPub, perms.PublicKeyMode)

	restoredPubText := readFile(curPub)
	var results []TargetResult
	for _, h := range hosts {
		prov := r.provider(h)
		tr := TargetResult{Alias: h.Alias, Provider: prov.Name()}
		if prov.Category() == "server" {
			st := netcheck.Check(h.Hostname, h.Port, h.RequiresVPN, deref(h.VPNName), "", 4*time.Second, true)
			if !st.Reachable {
				results = append(results, tr)
				continue
			}
		}
		restored := r.target(h, profile, curPub, restoredPubText, curPriv)
		out := prov.Deploy(restored)
		tr.Deployed = out.Method == "manual" || out.Verified
		tr.Verified = prov.Verify(restored)
		if curPubText != "" {
			removed := r.target(h, profile, curPub, curPubText, "")
			tr.Revoked = prov.Remove(removed)
		}
		results = append(results, tr)
	}
	report.Targets = results

	if report.OldFingerprint != "" {
		delete(r.inv.Keys, report.OldFingerprint)
	}
	ident := r.m.IdentityFile(profile, keyName)
	if rec, ok := r.inv.Keys[report.NewFingerprint]; ok {
		rec.Path = ident
		rec.Deployments = deployments(results, inventory.Today())
		r.inv.Keys[report.NewFingerprint] = rec
	}
	report.Committed = true
	log.Audit(r.p.AuditLog(), "rollback", log.Field{Key: "key", Value: keyName}, log.Field{Key: "restored", Value: report.NewFingerprint})
	return report, nil
}

// preservePair copies the keypair at src to dst without disturbing src.
//
// A hard link, not a copy: the two names share one inode, so the source keeps
// working while the archive exists and no private key bytes are written a second
// time. src and dst are both inside one profile directory, so a link is
// essentially always possible; a filesystem that refuses one (a bind mount over
// old/, say) falls back to copying, since preserving the outgoing key matters
// more than how it is preserved.
func preservePair(srcPriv, dstPriv string) error {
	for _, ext := range []string{"", ".pub"} {
		src, dst := srcPriv+ext, dstPriv+ext
		if !exists(src) {
			continue // a half pair is the caller's problem, not this one's
		}
		_ = os.Remove(dst) // the single archive slot holds one predecessor
		if err := os.Link(src, dst); err == nil {
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// copyFile is the fallback for preservePair. Private key modes are re-asserted
// by the caller's perms sweep; 0600 here means the file is never briefly
// readable by anyone else.
func copyFile(src, dst string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return fs.WriteTextAtomic(dst, string(body), perms.PrivateKeyMode)
}

// removePair deletes both halves of a keypair, ignoring absent files.
func removePair(priv string) {
	_ = os.Remove(priv)
	_ = os.Remove(priv + ".pub")
}

// rederivePub regenerates a public key file from its private key. Reports
// whether it succeeded - an encrypted key cannot be derived without its
// passphrase, and the caller has to say so rather than pretend.
func (r *Rotator) rederivePub(priv, pub string) bool {
	derived, _, err := r.ks.PublicFromPrivate(priv)
	if err != nil || derived == "" {
		return false
	}
	return fs.WriteTextAtomic(pub, derived+"\n", perms.PublicKeyMode) == nil
}

func deployments(results []TargetResult, date string) []inventory.Deployment {
	out := make([]inventory.Deployment, 0, len(results))
	d := date
	for _, t := range results {
		dd := d
		out = append(out, inventory.Deployment{Target: t.Alias, Method: t.Provider, Date: &dd, Verified: t.Verified})
	}
	return out
}

func allTrue(rs []TargetResult, pred func(TargetResult) bool) bool {
	for _, t := range rs {
		if !pred(t) {
			return false
		}
	}
	return true
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
