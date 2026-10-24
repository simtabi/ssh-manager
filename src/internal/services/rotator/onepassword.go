package rotator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/opstore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

// Item titles in the vault. The live key is titled with the key name, exactly
// one predecessor sits at .old (as old/ holds one on disk), and a rotation in
// flight is .staged until it commits.
func stagedTitle(keyName string) string { return keyName + ".staged" }
func oldTitle(keyName string) string    { return keyName + ".old" }

// agentFor is the agent a verify login uses: the 1Password agent when the
// profile keeps its keys there and the identity is a public key; none for a
// key file.
func (r *Rotator) agentFor(profile, identPath string) string {
	if identPath == "" || !r.m.Profiles[profile].InOnePassword() || !strings.HasSuffix(identPath, ".pub") {
		return ""
	}
	return r.m.Defaults.OnePasswordAgentSocket()
}

// rotateOnePassword is Rotate for a profile whose keys live in 1Password. The
// new key is generated inside 1Password as <key>.staged, deployed and verified
// through the 1Password agent, and only then retitled into place, the
// outgoing item becoming <key>.old. Nothing private is ever written to disk.
//
// It also moves a profile *into* 1Password: when the outgoing key is still a
// private key file (key_store was just switched), that pair is archived to
// old/ the way a file rotation archives it, and the new key is the vault item.
func (r *Rotator) rotateOnePassword(profile, keyName string, hosts []manifest.Host, allowUnverified bool) (RotateReport, error) {
	if err := r.op.Available(); err != nil {
		return RotateReport{}, err
	}
	vault := r.m.Profiles[profile].OPVault
	pdir := r.dir(profile)
	curPriv := filepath.Join(pdir, keyName)
	curPub := curPriv + ".pub"
	if !exists(curPub) {
		return RotateReport{}, fmt.Errorf("key not present: %s - run `sshmgr reconcile` first", curPub)
	}
	report := RotateReport{KeyName: keyName}
	if fp, err := r.ks.Fingerprint(curPub); err == nil {
		report.OldFingerprint = fp
	}
	oldPubText := readFile(curPub)

	if msgs := r.unreachable(hosts); len(msgs) > 0 {
		report.Message = "cannot rotate - " + strings.Join(msgs, "; ")
		log.Audit(r.p.AuditLog(), "rotate.unreachable", log.Field{Key: "key", Value: keyName})
		return report, nil
	}

	// 1. Stage: a fresh item in the vault, its public half in .staging/.
	if leftover, err := r.op.Get(vault, stagedTitle(keyName)); err == nil {
		if err := r.op.Archive(vault, leftover.ID); err != nil {
			return RotateReport{}, fmt.Errorf("a staged key from an earlier rotation is still in the vault "+
				"and could not be archived: %w", err)
		}
	} else if !errors.Is(err, opstore.ErrNotFound) {
		return RotateReport{}, err
	}
	staged, err := r.op.Create(vault, stagedTitle(keyName))
	if err != nil {
		return RotateReport{}, err
	}
	staging := filepath.Join(pdir, ".staging")
	_ = os.RemoveAll(staging)
	discard := func() {
		_ = os.RemoveAll(staging)
		_ = r.op.Archive(vault, staged.ID)
	}
	if err := fs.EnsureDir(staging, perms.DirMode); err != nil {
		discard()
		return RotateReport{}, err
	}
	stagedPub := filepath.Join(staging, keyName+".pub")
	if err := fs.WriteTextAtomic(stagedPub, staged.PublicKey+"\n", perms.PublicKeyMode); err != nil {
		discard()
		return RotateReport{}, err
	}
	if fp, err := r.ks.Fingerprint(stagedPub); err == nil {
		report.NewFingerprint = fp
	}

	// 2+3. Deploy and verify through the 1Password agent.
	stagedPubText := readFile(stagedPub)
	var results []TargetResult
	for _, h := range hosts {
		prov := r.provider(h)
		tr := TargetResult{Alias: h.Alias, Provider: prov.Name()}
		tgt := r.target(h, profile, stagedPub, stagedPubText, stagedPub)
		out := prov.Deploy(tgt)
		tr.Deployed = out.Method == "manual" || out.Verified
		tr.Verified = r.proveManual(h, prov, out, tgt, prov.Verify(tgt))
		if out.Method == "manual" {
			tr.ManageURL = prov.ManageURL(tgt)
		}
		results = append(results, tr)
	}
	report.Targets = results
	ready := allTrue(results, func(t TargetResult) bool { return t.Verified }) ||
		(allowUnverified && allTrue(results, func(t TargetResult) bool { return t.Deployed }))
	if !ready {
		for i, h := range hosts {
			if results[i].Deployed {
				_ = r.provider(h).Remove(r.target(h, profile, stagedPub, stagedPubText, ""))
			}
		}
		discard()
		report.Message = "verification failed on one or more targets - the staged key was archived " +
			"in 1Password (and pulled back from any target it reached), active key untouched. " +
			"(Use --allow-unverified to accept manual/web-panel targets.)"
		log.Audit(r.p.AuditLog(), "rotate.abort", log.Field{Key: "key", Value: keyName}, log.Field{Key: "old", Value: report.OldFingerprint})
		return report, nil
	}

	// 4. Commit. The outgoing key becomes the predecessor, in the vault or on
	// disk, then the staged item takes the live title. Each step that fails
	// puts back what had already moved.
	oldDir := filepath.Join(pdir, "old")
	if err := fs.EnsureDir(oldDir, perms.DirMode); err != nil {
		discard()
		return RotateReport{}, fmt.Errorf("could not prepare the archive directory, so the rotation "+
			"was not committed (the active key is untouched): %w", err)
	}
	// note tells a failure that happens after the earlier predecessor was
	// archived where that item went: everything else is put back, but an
	// archive is not undone.
	note := func(err error) error { return err }
	if prev, err := r.op.Get(vault, oldTitle(keyName)); err == nil {
		// One predecessor, as on disk: the older one goes to the vault's
		// Archive, where it can still be restored.
		if err := r.op.Archive(vault, prev.ID); err != nil {
			discard()
			return RotateReport{}, fmt.Errorf("could not archive the earlier predecessor %q, so the "+
				"rotation was not committed: %w", oldTitle(keyName), err)
		}
		note = func(err error) error {
			return fmt.Errorf("%w\n(the earlier predecessor %q had already been moved to the Archive "+
				"of vault %q; restore it from there if you still need it)", err, oldTitle(keyName), vault)
		}
	}
	var undo []func()
	rollbackCommit := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	cur, err := r.op.Get(vault, keyName)
	switch {
	case err == nil:
		if err := r.op.Rename(vault, cur.ID, oldTitle(keyName)); err != nil {
			discard()
			return RotateReport{}, note(fmt.Errorf("could not retitle the outgoing key, so the rotation "+
				"was not committed (the active key is untouched): %w", err))
		}
		undo = append(undo, func() { _ = r.op.Rename(vault, cur.ID, keyName) })
		// The vault now holds the predecessor, so a private key still at
		// old/<key> is the file-era key the move into 1Password archived. Left
		// there it would pose as the predecessor of a vault key - rollback
		// would refuse on it, and old/<key>.pub is about to become the vault
		// predecessor's, leaving a pair that does not match. Keep it, aside.
		if exists(filepath.Join(oldDir, keyName)) {
			restore, err := r.setAsideFileEraKey(oldDir, keyName, filepath.Join(oldDir, keyName+".pub"))
			if err != nil {
				rollbackCommit()
				discard()
				return RotateReport{}, note(fmt.Errorf("could not set aside the key file from before the "+
					"profile moved to 1Password, so the rotation was undone: %w", err))
			}
			undo = append(undo, restore)
		}
	case errors.Is(err, opstore.ErrNotFound) && exists(curPriv):
		// Moving into 1Password: the outgoing key is a file pair.
		oldPriv := filepath.Join(oldDir, keyName)
		if err := os.Rename(curPriv, oldPriv); err != nil {
			discard()
			return RotateReport{}, note(fmt.Errorf("could not archive the outgoing key file, so the "+
				"rotation was not committed: %w", err))
		}
		undo = append(undo, func() { _ = os.Rename(oldPriv, curPriv) })
	case errors.Is(err, opstore.ErrNotFound):
		// A .pub with no item and no private key: nothing to retire in the vault.
	default:
		discard()
		return RotateReport{}, note(err)
	}
	if err := r.op.Rename(vault, staged.ID, keyName); err != nil {
		rollbackCommit()
		discard()
		return RotateReport{}, note(fmt.Errorf("could not give the new key its title, so the rotation was "+
			"undone and the previous key is active again: %w", err))
	}
	oldPub := filepath.Join(oldDir, keyName+".pub")
	if err := copyFile(curPub, oldPub); err != nil {
		_ = r.op.Rename(vault, staged.ID, stagedTitle(keyName))
		rollbackCommit()
		discard()
		return RotateReport{}, note(fmt.Errorf("could not archive the outgoing public key, so the rotation "+
			"was undone: %w", err))
	}
	if err := os.Rename(stagedPub, curPub); err != nil {
		_ = r.op.Rename(vault, staged.ID, stagedTitle(keyName))
		rollbackCommit()
		discard()
		return RotateReport{}, note(fmt.Errorf("could not move the new public key into place, so the "+
			"rotation was undone: %w", err))
	}
	_ = perms.SetPerms(curPub, perms.PublicKeyMode)
	_ = perms.SetPerms(oldPub, perms.PublicKeyMode)
	_ = os.RemoveAll(staging)

	for i := range hosts {
		results[i].Revoked = r.provider(hosts[i]).Remove(r.target(hosts[i], profile, oldPub, oldPubText, ""))
	}
	report.Targets = results
	r.updateInventory(profile, keyName, report, results)
	report.Committed = true
	log.Audit(r.p.AuditLog(), "rotate", log.Field{Key: "key", Value: keyName}, log.Field{Key: "store", Value: "1password"},
		log.Field{Key: "old", Value: report.OldFingerprint}, log.Field{Key: "new", Value: report.NewFingerprint})
	return report, nil
}

// rollbackOnePassword is Rollback for a profile whose keys live in 1Password:
// the <key>.old item takes the live title back, the rotated-in item goes to the
// vault's Archive (recoverable, never deleted), and the predecessor's public key
// returns from old/.
func (r *Rotator) rollbackOnePassword(profile, keyName string, hosts []manifest.Host) (RotateReport, error) {
	if err := r.op.Available(); err != nil {
		return RotateReport{}, err
	}
	vault := r.m.Profiles[profile].OPVault
	pdir := r.dir(profile)
	curPub := filepath.Join(pdir, keyName+".pub")
	oldDir := filepath.Join(pdir, "old")
	oldPub := filepath.Join(oldDir, keyName+".pub")
	// A key file at old/<key> is the predecessor only while old/<key>.pub is
	// its public half: then the profile has rotated once since moving into
	// 1Password and the way back is the file store. An earlier sshmgr left that
	// file in place across later vault rotations, which overwrote the .pub with
	// the vault predecessor's, so presence alone is not proof. A key that
	// cannot be derived (encrypted) is given the benefit of the doubt and
	// refused, as before.
	stale := false
	if oldPriv := filepath.Join(oldDir, keyName); exists(oldPriv) {
		derived, _, derr := r.ks.PublicFromPrivate(oldPriv)
		if derr != nil || derived == "" || sameKey(derived, readFile(oldPub)) {
			return RotateReport{}, fmt.Errorf("the predecessor of %q is a key file from before the profile "+
				"moved to 1Password; set key_store back to %q to roll back to it", keyName, manifest.KeyStoreFile)
		}
		stale = true
	}
	prev, err := r.op.Get(vault, oldTitle(keyName))
	if errors.Is(err, opstore.ErrNotFound) || !exists(oldPub) {
		return RotateReport{}, fmt.Errorf("no predecessor to roll back to for %q (want item %q in vault %q "+
			"and %s)", keyName, oldTitle(keyName), vault, oldPub)
	}
	if err != nil {
		return RotateReport{}, err
	}
	if stale {
		// Out of the predecessor's place before the rollback uses it. This is
		// not undone if a later step fails: the file is stale either way, and
		// set aside it stays a recoverable, matching pair.
		if _, err := r.setAsideFileEraKey(oldDir, keyName, ""); err != nil {
			return RotateReport{}, fmt.Errorf("could not set aside the stale key file from before the "+
				"profile moved to 1Password, so nothing was rolled back: %w", err)
		}
	}
	report := RotateReport{KeyName: keyName}
	if fp, err := r.ks.Fingerprint(curPub); err == nil {
		report.OldFingerprint = fp
	}
	curPubText := readFile(curPub)
	if fp, err := r.ks.Fingerprint(oldPub); err == nil {
		report.NewFingerprint = fp
	}

	cur, err := r.op.Get(vault, keyName)
	if err != nil && !errors.Is(err, opstore.ErrNotFound) {
		return RotateReport{}, err
	}
	if err == nil {
		// Out of the live title first, so the predecessor can take it.
		if err := r.op.Rename(vault, cur.ID, keyName+".rolled-back"); err != nil {
			return RotateReport{}, fmt.Errorf("could not retitle the rotated-in key, so nothing was "+
				"rolled back: %w", err)
		}
	}
	if err := r.op.Rename(vault, prev.ID, keyName); err != nil {
		if cur.ID != "" {
			_ = r.op.Rename(vault, cur.ID, keyName)
		}
		return RotateReport{}, fmt.Errorf("could not restore the predecessor's title, so nothing was "+
			"rolled back: %w", err)
	}
	if err := os.Rename(oldPub, curPub); err != nil {
		return RotateReport{}, fmt.Errorf("the predecessor is the live item %q again, but its public key "+
			"could not be moved back from %s to %s - move it by hand: %w", keyName, oldPub, curPub, err)
	}
	_ = perms.SetPerms(curPub, perms.PublicKeyMode)
	if cur.ID != "" {
		_ = r.op.Archive(vault, cur.ID)
	}
	return r.finishRollback(profile, keyName, hosts, curPub, curPub, curPubText, report)
}

// setAsideFileEraKey moves the private key at old/<key> - the file-era key a
// move into 1Password archived - to old/<key>.file-era, and writes its public
// half beside it so the pair stays usable. Nothing is deleted: key material is
// only ever moved. An existing .file-era is never overwritten; the next free
// numbered name is used instead.
//
// The public half is derived from the private key when it can be; for an
// encrypted key it is copied from pubFallback, which the caller passes only
// when that file is known to be this key's (empty: none is written). The
// returned func puts the key back where it was.
func (r *Rotator) setAsideFileEraKey(oldDir, keyName, pubFallback string) (func(), error) {
	from := filepath.Join(oldDir, keyName)
	to := filepath.Join(oldDir, keyName+".file-era")
	for n := 2; exists(to) || exists(to+".pub"); n++ {
		to = filepath.Join(oldDir, fmt.Sprintf("%s.file-era.%d", keyName, n))
	}
	if err := os.Rename(from, to); err != nil {
		return nil, err
	}
	wrotePub := r.rederivePub(to, to+".pub")
	if !wrotePub && pubFallback != "" && exists(pubFallback) {
		wrotePub = fs.WriteTextAtomic(to+".pub", readFile(pubFallback), perms.PublicKeyMode) == nil
	}
	return func() {
		_ = os.Rename(to, from)
		if wrotePub {
			_ = os.Remove(to + ".pub")
		}
	}, nil
}

// sameKey reports whether two OpenSSH public key lines carry the same key,
// ignoring the comment.
func sameKey(a, b string) bool {
	fa, fb := strings.Fields(a), strings.Fields(b)
	return len(fa) >= 2 && len(fb) >= 2 && fa[0] == fb[0] && fa[1] == fb[1]
}
