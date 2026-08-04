// Package lifecycle removes a profile or a key completely, as one guarded
// transaction.
//
// Deleting used to mean editing the manifest and nothing else: key files stayed,
// the profile directory stayed, known_hosts kept pins for hosts that no longer
// existed, and ~/.ssh/config only caught up on the next reconcile - so the
// immediate result of "delete" was a tree doctor then reported as broken. This
// package finishes the job: manifest and inventory (via editor), then the
// rendered config, then reference-counted known_hosts pins, and finally the key
// files themselves - those last only under Purge, because a key file is the one
// thing here that cannot be reconstructed from the manifest.
//
// The caller owns the lock, the snapshot and the encrypted backup (the CLI's
// mutation guard), the same way it does for keygen and rotate.
package lifecycle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/editor"
	"github.com/simtabi/ssh-manager/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Options are the destructive opt-ins. Both default off: a delete that only
// edits state is recoverable from the manifest plus the key files still on disk.
type Options struct {
	// Purge removes the key files too, and the profile directory when nothing
	// unmanaged is left in it.
	Purge bool
	// Revoke asks the provider adapters to remove the deployed public key from
	// its targets first.
	Revoke bool
}

// Result is what the transaction actually did.
type Result struct {
	Removed       string   // "profile work" | "key work/work_gh-ed25519"
	Revoked       []string // targets the key was revoked from
	PrunedRecords []string // inventory records dropped
	RemovedFiles  []string // key files deleted (Purge only)
	RemovedDirs   []string // directories deleted once empty (Purge only)
	KeptFiles     []string // key files deliberately left behind
	UnmanagedLeft []string // directories left in place, holding files we did not create
	ConfigWritten []string // config files re-rendered
	PrunedPins    int      // known_hosts lines removed

	// UnwiredKeys are keys the deletion left with no host, but which their
	// profile still declares - so they remain sshmgr's, just unused.
	UnwiredKeys []string
	// OrphanedKeys are keys the deletion removed from the manifest entirely,
	// because nothing declared them and only the deleted host named them. Their
	// files are still on disk and nothing tracks them any more.
	OrphanedKeys []string
}

// Format renders the human-readable summary.
func (r Result) Format() string {
	lines := []string{"deleted " + r.Removed}
	add := func(label string, items []string) {
		if len(items) > 0 {
			lines = append(lines, fmt.Sprintf("  %s: %s", label, strings.Join(items, ", ")))
		}
	}
	add("revoked from", r.Revoked)
	add("pruned inventory", r.PrunedRecords)
	add("removed files", r.RemovedFiles)
	add("removed dirs", r.RemovedDirs)
	if r.PrunedPins > 0 {
		lines = append(lines, fmt.Sprintf("  pruned known_hosts: %d line(s) no host needs any more", r.PrunedPins))
	}
	add("re-rendered", r.ConfigWritten)
	for _, ref := range r.UnwiredKeys {
		lines = append(lines, fmt.Sprintf("  %s is now UNWIRED: its profile still declares it, but no "+
			"host uses it.", ref))
		lines = append(lines, fmt.Sprintf("    wire it with `sshmgr host edit <profile> <alias> "+
			"--key-name %s`, or remove it with `sshmgr key delete %s --purge`.", keyNameOf(ref), ref))
	}
	for _, ref := range r.OrphanedKeys {
		lines = append(lines, fmt.Sprintf("  %s left the manifest with the host: only that host named "+
			"it, and no keys entry declared it.", ref))
	}
	if len(r.KeptFiles) > 0 {
		lines = append(lines, fmt.Sprintf("  kept %d key file(s) on disk: %s",
			len(r.KeptFiles), strings.Join(r.KeptFiles, ", ")))
		lines = append(lines, "  re-run with --purge to delete them (doctor reports them as orphaned until then).")
	}
	for _, dir := range r.UnmanagedLeft {
		lines = append(lines, "  left "+dir+" in place: it still holds files sshmgr did not create.")
	}
	return strings.Join(lines, "\n")
}

// Service performs profile and key deletions against one home.
type Service struct {
	p               paths.Paths
	emitUseKeychain bool
}

// New builds a lifecycle service. emitUseKeychain matches the platform (macOS
// only), as everywhere else that renders config.
func New(p paths.Paths, emitUseKeychain bool) *Service {
	return &Service{p: p, emitUseKeychain: emitUseKeychain}
}

// DeleteProfile removes a profile and everything the manifest says belongs to
// it: its hosts, its keys' inventory records, its Host blocks in the rendered
// config, its hosts' known_hosts pins (only those no surviving host still needs)
// and, under Purge, its key files and directory.
func (s *Service) DeleteProfile(name string, opt Options) (Result, error) {
	before, err := manifest.Load(s.p.Manifest())
	if err != nil {
		return Result{}, err
	}
	if _, ok := before.Profiles[name]; !ok {
		return Result{}, fmt.Errorf("unknown profile: %q", name)
	}
	// Resolve the file paths while the profile still exists to name them.
	files, err := s.profileKeyFiles(before, name)
	if err != nil {
		return Result{}, err
	}

	ed := editor.New(s.p)
	del, err := ed.DeleteProfile(name, opt.Revoke)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Removed: "profile " + name, Revoked: del.Revoked, PrunedRecords: del.PrunedKeys,
	}
	if err := s.finish(&res, files, filepath.Join(s.p.SSHDir, "profiles", name), opt); err != nil {
		return res, err
	}
	return res, nil
}

// DeleteHost removes one host: its manifest entry, its Host block in the
// rendered config, and any known_hosts pin no remaining host needs.
//
// Keys are not the host's to take - a key can outlive the host that used it -
// so what happens to the key it named depends on what the manifest says after
// the delete. Still used by another host: nothing to report. Still declared in
// the profile's keys list: UNWIRED, reported with the two ways out, files
// untouched even under Purge, because the profile still owns it. Neither: the
// key left the manifest along with the host, its files are now tracked by
// nothing, and Purge is what removes them.
func (s *Service) DeleteHost(profile, alias string, opt Options) (Result, error) {
	before, err := manifest.Load(s.p.Manifest())
	if err != nil {
		return Result{}, err
	}
	host, err := findHost(before, profile, alias)
	if err != nil {
		return Result{}, err
	}
	kname, err := before.ResolvedKeyName(profile, host)
	if err != nil {
		return Result{}, err
	}
	ref := manifest.KeyRef{Profile: profile, KeyName: kname}
	files, err := s.filesFor(before, ref)
	if err != nil {
		return Result{}, err
	}

	del, err := editor.New(s.p).DeleteHost(profile, alias, opt.Revoke)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Removed: fmt.Sprintf("host %s (profile %s)", alias, profile),
		Revoked: del.Revoked, PrunedRecords: del.PrunedKeys,
	}

	after, err := manifest.Load(s.p.Manifest())
	if err != nil {
		return res, err
	}
	stranded, err := classify(after, ref)
	if err != nil {
		return res, err
	}
	var purgeable []string
	switch stranded {
	case keyUnwired:
		res.UnwiredKeys = append(res.UnwiredKeys, ref.String())
	case keyOrphaned:
		res.OrphanedKeys = append(res.OrphanedKeys, ref.String())
		purgeable = files
	}
	// "" for the profile directory: the profile still exists, so removing its
	// directory is never this command's business even when the purge empties it.
	if err := s.finish(&res, purgeable, "", opt); err != nil {
		return res, err
	}
	return res, nil
}

// strandState is what became of a key once the host that named it was deleted.
type strandState int

const (
	keyStillUsed strandState = iota // another host resolves to it
	keyUnwired                      // the profile still declares it; nothing uses it
	keyOrphaned                     // gone from the manifest entirely
)

func classify(after *manifest.Manifest, ref manifest.KeyRef) (strandState, error) {
	hosts, err := after.HostsForKey(ref)
	if err != nil {
		return keyStillUsed, err
	}
	if len(hosts) > 0 {
		return keyStillUsed, nil
	}
	if _, declared := after.KeySpecFor(ref); declared {
		return keyUnwired, nil
	}
	return keyOrphaned, nil
}

func findHost(m *manifest.Manifest, profile, alias string) (manifest.Host, error) {
	prof, ok := m.Profiles[profile]
	if !ok {
		return manifest.Host{}, fmt.Errorf("unknown profile: %q", profile)
	}
	for _, h := range prof.Hosts {
		if h.Alias == alias {
			return h, nil
		}
	}
	return manifest.Host{}, fmt.Errorf("unknown host %q in profile %q", alias, profile)
}

// keyNameOf is the key half of a "profile/key" reference, for building the
// command that fixes an unwired key.
func keyNameOf(ref string) string {
	if _, name, ok := strings.Cut(ref, "/"); ok {
		return name
	}
	return ref
}

// DeleteKey removes one key: its declaration, its inventory record and, under
// Purge, its files. It refuses while a host still uses the key (see
// editor.DeleteKey) - the config would otherwise keep pointing at a file that no
// longer exists.
func (s *Service) DeleteKey(ref manifest.KeyRef, opt Options) (Result, error) {
	m, err := manifest.Load(s.p.Manifest())
	if err != nil {
		return Result{}, err
	}
	inv, err := inventory.Load(s.p.Inventory())
	if err != nil {
		return Result{}, err
	}
	row, err := keysvc.New(m, inv, s.p.SSHDir).Row(ref)
	if err != nil {
		return Result{}, err
	}

	del, err := editor.New(s.p).DeleteKey(ref, opt.Revoke)
	if err != nil {
		return Result{}, err
	}
	res := Result{Removed: "key " + ref.String(), Revoked: del.Revoked, PrunedRecords: del.PrunedKeys}
	// No config re-render and no known_hosts pruning: a deletable key is by
	// definition wired to no host, so neither the rendered config nor any pin
	// mentions it.
	if err := s.purgeOrKeep(&res, s.keyFiles(row), filepath.Join(s.p.SSHDir, "profiles", ref.Profile), opt); err != nil {
		return res, err
	}
	return res, nil
}

// finish re-renders the config, prunes now-unreferenced known_hosts pins, and
// applies the purge decision. Order matters: the manifest is already saved, so
// both the renderer and the pruner see the post-delete world.
func (s *Service) finish(res *Result, files []string, profileDir string, opt Options) error {
	m, err := manifest.Load(s.p.Manifest())
	if err != nil {
		return err
	}
	written, err := configsvc.New(s.p.SSHDir, m, s.emitUseKeychain).Write(false)
	if err != nil {
		return err
	}
	if written != nil {
		res.ConfigWritten = append(res.ConfigWritten, written.Written...)
	}
	pruned, err := knownhosts.New(s.p.SSHDir).Prune(m)
	if err != nil {
		return err
	}
	res.PrunedPins = pruned
	return s.purgeOrKeep(res, files, profileDir, opt)
}

// purgeOrKeep deletes the key files under Purge and records what was left
// otherwise. With a profileDir it also removes that directory under Purge, but
// only once every file in it is accounted for - a file sshmgr did not create is
// reported and left alone, since deciding it is disposable is not this command's
// call. An empty profileDir means the profile survives the deletion, so no
// directory is touched at all.
func (s *Service) purgeOrKeep(res *Result, files []string, profileDir string, opt Options) error {
	if !opt.Purge {
		for _, f := range files {
			if exists(f) {
				res.KeptFiles = append(res.KeptFiles, f)
			}
		}
		return nil
	}
	for _, f := range files {
		if !exists(f) {
			continue
		}
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("could not remove %s: %w", f, err)
		}
		res.RemovedFiles = append(res.RemovedFiles, f)
	}
	if profileDir == "" {
		return nil
	}
	// old/ holds rotation predecessors of the keys just removed; drop it when the
	// purge emptied it, then the profile directory itself.
	for _, dir := range []string{filepath.Join(profileDir, "old"), profileDir} {
		if !exists(dir) {
			continue
		}
		empty, err := isEmptyDir(dir)
		if err != nil {
			return err
		}
		if !empty {
			res.UnmanagedLeft = append(res.UnmanagedLeft, dir)
			break
		}
		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("could not remove %s: %w", dir, err)
		}
		res.RemovedDirs = append(res.RemovedDirs, dir)
	}
	return nil
}

// profileKeyFiles lists every file on disk belonging to a profile's keys: each
// pair plus any rotation predecessor parked in old/.
func (s *Service) profileKeyFiles(m *manifest.Manifest, profile string) ([]string, error) {
	inv, err := inventory.Load(s.p.Inventory())
	if err != nil {
		return nil, err
	}
	// Every key, then filter by owner: passing the profile as a selector would
	// also match a host alias or key name that happens to share its name, and
	// would error out on a profile that owns no keys at all - which is not a
	// failure here, just nothing to remove.
	rows, err := keysvc.New(m, inv, s.p.SSHDir).Rows("")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, row := range rows {
		if row.Ref.Profile != profile {
			continue
		}
		files = append(files, s.keyFiles(row)...)
	}
	return files, nil
}

// filesFor lists the paths one key occupies, resolved against a manifest that
// still knows about it.
func (s *Service) filesFor(m *manifest.Manifest, ref manifest.KeyRef) ([]string, error) {
	inv, err := inventory.Load(s.p.Inventory())
	if err != nil {
		return nil, err
	}
	row, err := keysvc.New(m, inv, s.p.SSHDir).Row(ref)
	if err != nil {
		return nil, err
	}
	return s.keyFiles(row), nil
}

// keyFiles lists the paths one key can occupy: the pair, and the predecessor
// pair a rotation parked in old/.
func (s *Service) keyFiles(row keysvc.Row) []string {
	old := filepath.Join(filepath.Dir(row.PrivatePath), "old", filepath.Base(row.PrivatePath))
	return []string{row.PrivatePath, row.PublicPath, old, old + ".pub"}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func isEmptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}
