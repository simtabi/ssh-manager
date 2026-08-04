// Package editor does manifest editing - profile/host add·edit·delete - ported
// from services/editor.py. Edits go through the manifest (never a hand-edited
// config), are validated, and written atomically. Delete prunes the inventory
// deployment record so no dangling tracking is left behind.
//
// Note: remote key REVOCATION on delete needs the provider adapters (gh/glab/REST),
// which are a later wave; until then revoke prunes local deployment tracking but
// does not call a remote (matching v1's behavior for manual/web-panel providers).
package editor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/log"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// DeleteResult is what one manifest-level deletion changed. It is data for the
// caller to fold into its own report - it carries no Format of its own, because
// the manifest half of a deletion is no longer the whole story: the lifecycle
// service composes this with the config re-render, the known_hosts pruning and
// whatever happened to the key files, and only it can describe the outcome
// truthfully.
type DeleteResult struct {
	Removed    string
	Revoked    []string
	PrunedKeys []string
}

// Editor edits the manifest at the resolved home.
type Editor struct {
	p paths.Paths
}

// New builds a manifest editor.
func New(p paths.Paths) *Editor { return &Editor{p: p} }

func (e *Editor) load() (*manifest.Manifest, error) { return manifest.Load(e.p.Manifest()) }

// save validates then writes (so a bad edit can't be persisted).
func (e *Editor) save(m *manifest.Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	return m.Save(e.p.Manifest())
}

// --- profiles --------------------------------------------------------------

// AddProfile adds a new profile. keyScope defaults to per_service.
func (e *Editor) AddProfile(name, keyScope string, keyName *string) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	if _, ok := m.Profiles[name]; ok {
		return fmt.Errorf("profile %q already exists", name)
	}
	if keyScope == "" {
		keyScope = "per_service"
	}
	m.SetProfile(name, manifest.Profile{KeyScope: keyScope, KeyName: keyName})
	if err := e.save(m); err != nil {
		return err
	}
	log.Audit(e.p.AuditLog(), "profile.add", log.Field{Key: "profile", Value: name})
	return nil
}

// EditProfile updates a profile's key_scope and/or key_name (nil/empty keeps).
func (e *Editor) EditProfile(name string, keyScope *string, keyName *string) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	p, ok := m.Profiles[name]
	if !ok {
		return fmt.Errorf("unknown profile: %q", name)
	}
	scope := p.KeyScope
	if keyScope != nil && *keyScope != "" {
		scope = *keyScope
	}
	if keyName != nil {
		p.KeyName = keyName
	}
	// Mutate the loaded profile rather than rebuilding one from the fields this
	// command knows about, so a field it does not edit (keys) survives the edit.
	p.KeyScope = scope
	m.SetProfile(name, p)
	if err := e.save(m); err != nil {
		return err
	}
	log.Audit(e.p.AuditLog(), "profile.edit", log.Field{Key: "profile", Value: name})
	return nil
}

// DeleteProfile removes a profile, revoking/pruning its hosts' keys.
func (e *Editor) DeleteProfile(name string, revoke bool) (DeleteResult, error) {
	m, err := e.load()
	if err != nil {
		return DeleteResult{}, err
	}
	if _, ok := m.Profiles[name]; !ok {
		return DeleteResult{}, fmt.Errorf("unknown profile: %q", name)
	}
	inv, err := inventory.Load(e.p.Inventory())
	if err != nil {
		return DeleteResult{}, err
	}
	res := DeleteResult{Removed: "profile " + name}
	// Every key the profile owns, not just the ones its hosts resolve to: a key
	// the profile declares without a host has an inventory record too, and
	// leaving it behind would point tracking at a profile that no longer exists.
	refs, err := m.KeyRefs()
	if err != nil {
		return DeleteResult{}, err
	}
	affected := map[string]bool{}
	for _, ref := range refs {
		if ref.Profile == name {
			affected[m.IdentityFile(ref.Profile, ref.KeyName)] = true
		}
	}
	for _, host := range m.Profiles[name].Hosts {
		e.revokeHost(m, inv, name, host, revoke, &res)
	}
	m.DeleteProfile(name)
	if err := e.pruneIdents(m, inv, affected, &res); err != nil {
		return DeleteResult{}, err
	}
	if err := e.save(m); err != nil {
		return DeleteResult{}, err
	}
	if err := inv.Save(e.p.Inventory()); err != nil {
		return DeleteResult{}, err
	}
	log.Audit(e.p.AuditLog(), "profile.delete", log.Field{Key: "profile", Value: name}, log.Field{Key: "revoke", Value: revoke})
	return res, nil
}

// --- keys ------------------------------------------------------------------

// AddKey declares a key on a profile and, when hostAlias is set, points that
// host at it. Type and rotateAfterDays are optional overrides of the manifest
// defaults. It only edits the manifest - minting the key file is the caller's
// next step, so a failed edit never leaves a key on disk nothing refers to.
func (e *Editor) AddKey(profile, name string, keyType *string, rotateAfterDays *int, hostAlias string) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	p, ok := m.Profiles[profile]
	if !ok {
		return fmt.Errorf("unknown profile: %q", profile)
	}
	for _, k := range p.Keys {
		if k.Name == name {
			return fmt.Errorf("profile %q already declares key %q", profile, name)
		}
	}
	if hostAlias != "" {
		// In a shared profile every host uses the profile's key_name, so wiring
		// one host to a different key would silently do nothing.
		if p.KeyScope == "shared" {
			return fmt.Errorf("profile %q is shared - every host uses its key_name; "+
				"use `sshmgr profile edit %s --key-name %s` to switch the whole profile",
				profile, profile, name)
		}
		idx, host, err := findHost(m, profile, hostAlias)
		if err != nil {
			return err
		}
		host.KeyName = &name
		p.Hosts[idx] = host
	}
	p.Keys = append(p.Keys, manifest.KeySpec{Name: name, Type: keyType, RotateAfterDays: rotateAfterDays})
	m.SetProfile(profile, p)
	if err := e.save(m); err != nil {
		return err
	}
	log.Audit(e.p.AuditLog(), "key.add",
		log.Field{Key: "profile", Value: profile},
		log.Field{Key: "key", Value: name},
		log.Field{Key: "host", Value: hostAlias})
	return nil
}

// DeleteKey removes a key's declaration from its profile and drops its inventory
// record. It refuses while any host still resolves to the key: deleting it then
// would leave a Host block pointing at an IdentityFile that no longer exists,
// which ssh reports as a bare permission denial. Key files on disk are the
// caller's to remove (see the lifecycle service) so an accidental delete costs
// nothing but a manifest edit.
func (e *Editor) DeleteKey(ref manifest.KeyRef, revoke bool) (DeleteResult, error) {
	m, err := e.load()
	if err != nil {
		return DeleteResult{}, err
	}
	p, ok := m.Profiles[ref.Profile]
	if !ok {
		return DeleteResult{}, fmt.Errorf("unknown profile: %q", ref.Profile)
	}
	hosts, err := m.HostsForKey(ref)
	if err != nil {
		return DeleteResult{}, err
	}
	if len(hosts) > 0 {
		aliases := make([]string, 0, len(hosts))
		for _, h := range hosts {
			aliases = append(aliases, h.Alias)
		}
		return DeleteResult{}, fmt.Errorf("key %s is still used by %d host(s): %s - "+
			"point them at another key (`sshmgr host edit <alias> --key-name ...`) or "+
			"delete them first", ref, len(hosts), strings.Join(aliases, ", "))
	}
	kept := p.Keys[:0:0]
	found := false
	for _, k := range p.Keys {
		if k.Name == ref.KeyName {
			found = true
			continue
		}
		kept = append(kept, k)
	}
	if !found {
		return DeleteResult{}, fmt.Errorf("profile %q declares no key %q", ref.Profile, ref.KeyName)
	}
	p.Keys = kept
	m.SetProfile(ref.Profile, p)

	inv, err := inventory.Load(e.p.Inventory())
	if err != nil {
		return DeleteResult{}, err
	}
	res := DeleteResult{Removed: "key " + ref.String()}
	ident := m.IdentityFile(ref.Profile, ref.KeyName)
	for fp, rec := range inv.Keys {
		if rec.Path != ident {
			continue
		}
		if revoke {
			for _, d := range rec.Deployments {
				if removeFromTarget() {
					res.Revoked = append(res.Revoked, d.Target)
				}
			}
		}
		res.PrunedKeys = append(res.PrunedKeys, basename(rec.Path))
		delete(inv.Keys, fp)
	}
	if err := e.save(m); err != nil {
		return DeleteResult{}, err
	}
	if err := inv.Save(e.p.Inventory()); err != nil {
		return DeleteResult{}, err
	}
	log.Audit(e.p.AuditLog(), "key.delete",
		log.Field{Key: "profile", Value: ref.Profile},
		log.Field{Key: "key", Value: ref.KeyName},
		log.Field{Key: "revoke", Value: revoke})
	return res, nil
}

// --- hosts -----------------------------------------------------------------

// HostFields are the optional attributes for add/edit host (nil = unset/keep).
type HostFields struct {
	Hostname *string
	User     *string
	Port     *int
	Provider *string
	TokenEnv *string
	KeyName  *string
	Tags     []string
}

// AddHost adds a host to a profile.
func (e *Editor) AddHost(profile, alias string, f HostFields) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	if _, ok := m.Profiles[profile]; !ok {
		return fmt.Errorf("unknown profile: %q", profile)
	}
	for _, h := range m.Profiles[profile].Hosts {
		if h.Alias == alias {
			return fmt.Errorf("host %q already exists in %q", alias, profile)
		}
	}
	port := 22
	if f.Port != nil {
		port = *f.Port
	}
	host := manifest.Host{
		Alias: alias, Hostname: deref(f.Hostname), User: deref(f.User), Port: port,
		Provider: f.Provider, TokenEnv: f.TokenEnv, KeyName: f.KeyName, Tags: f.Tags,
	}
	p := m.Profiles[profile]
	p.Hosts = append(p.Hosts, host)
	m.SetProfile(profile, p)
	if err := e.save(m); err != nil {
		return err
	}
	log.Audit(e.p.AuditLog(), "host.add", log.Field{Key: "profile", Value: profile}, log.Field{Key: "alias", Value: alias})
	return nil
}

// EditHost updates a host's fields (only the non-nil ones).
func (e *Editor) EditHost(profile, alias string, f HostFields) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	idx, host, err := findHost(m, profile, alias)
	if err != nil {
		return err
	}
	if f.Hostname != nil {
		host.Hostname = *f.Hostname
	}
	if f.User != nil {
		host.User = *f.User
	}
	if f.Port != nil {
		host.Port = *f.Port
	}
	if f.Provider != nil {
		host.Provider = f.Provider
	}
	if f.TokenEnv != nil {
		host.TokenEnv = f.TokenEnv
	}
	if f.KeyName != nil {
		host.KeyName = f.KeyName
	}
	p := m.Profiles[profile]
	p.Hosts[idx] = host
	m.SetProfile(profile, p)
	if err := e.save(m); err != nil {
		return err
	}
	log.Audit(e.p.AuditLog(), "host.edit", log.Field{Key: "profile", Value: profile}, log.Field{Key: "alias", Value: alias})
	return nil
}

// DeleteHost removes a host, revoking/pruning its key.
func (e *Editor) DeleteHost(profile, alias string, revoke bool) (DeleteResult, error) {
	m, err := e.load()
	if err != nil {
		return DeleteResult{}, err
	}
	idx, host, err := findHost(m, profile, alias)
	if err != nil {
		return DeleteResult{}, err
	}
	inv, err := inventory.Load(e.p.Inventory())
	if err != nil {
		return DeleteResult{}, err
	}
	res := DeleteResult{Removed: fmt.Sprintf("host %s (profile %s)", alias, profile)}
	kn, err := m.ResolvedKeyName(profile, host)
	if err != nil {
		return DeleteResult{}, err
	}
	affected := map[string]bool{m.IdentityFile(profile, kn): true}
	e.revokeHost(m, inv, profile, host, revoke, &res)
	p := m.Profiles[profile]
	p.Hosts = append(p.Hosts[:idx], p.Hosts[idx+1:]...)
	m.SetProfile(profile, p)
	if err := e.pruneIdents(m, inv, affected, &res); err != nil {
		return DeleteResult{}, err
	}
	if err := e.save(m); err != nil {
		return DeleteResult{}, err
	}
	if err := inv.Save(e.p.Inventory()); err != nil {
		return DeleteResult{}, err
	}
	log.Audit(e.p.AuditLog(), "host.delete", log.Field{Key: "profile", Value: profile}, log.Field{Key: "alias", Value: alias}, log.Field{Key: "revoke", Value: revoke})
	return res, nil
}

// --- helpers ---------------------------------------------------------------

func findHost(m *manifest.Manifest, profile, alias string) (int, manifest.Host, error) {
	if _, ok := m.Profiles[profile]; !ok {
		return 0, manifest.Host{}, fmt.Errorf("unknown profile: %q", profile)
	}
	for i, h := range m.Profiles[profile].Hosts {
		if h.Alias == alias {
			return i, h, nil
		}
	}
	return 0, manifest.Host{}, fmt.Errorf("unknown host %q in profile %q", alias, profile)
}

// revokeHost drops this host's deployment entry from the inventory record (and,
// when adapters exist, would revoke the key from the remote target - a no-op for
// now). The record itself is pruned later by pruneIdents.
func (e *Editor) revokeHost(m *manifest.Manifest, inv *inventory.Inventory, profile string, host manifest.Host, revoke bool, res *DeleteResult) {
	kn, err := m.ResolvedKeyName(profile, host)
	if err != nil {
		return
	}
	ident := m.IdentityFile(profile, kn)
	for fp, rec := range inv.Keys {
		if rec.Path != ident {
			continue
		}
		hasDep := false
		for _, d := range rec.Deployments {
			if d.Target == host.Alias {
				hasDep = true
				break
			}
		}
		if revoke && hasDep && removeFromTarget() {
			res.Revoked = append(res.Revoked, host.Alias)
		}
		kept := rec.Deployments[:0:0]
		for _, d := range rec.Deployments {
			if d.Target != host.Alias {
				kept = append(kept, d)
			}
		}
		rec.Deployments = kept
		inv.Keys[fp] = rec
	}
}

// removeFromTarget would call the provider adapter to revoke the key remotely.
// The adapters are a later wave, so this is a no-op (matching the base provider).
func removeFromTarget() bool { return false }

// pruneIdents drops inventory records for the affected key paths that nothing in
// the surviving manifest owns any more.
//
// "Owns", not "has a host for". A profile can declare a key no host references,
// and that key still has files on disk and a record tracking its expiry and
// deployments. Deriving the surviving set from hosts alone silently dropped the
// record of a key that had merely become unwired - deleting the last host using
// a declared key left the key itself in place with nothing tracking it, which
// expiry and rotation then could not see.
//
// Failing to compute the surviving set is not a licence to prune - it means we
// cannot prove a record is unused - so the error is returned rather than
// swallowed per host as it used to be.
func (e *Editor) pruneIdents(m *manifest.Manifest, inv *inventory.Inventory, affected map[string]bool, res *DeleteResult) error {
	refs, err := m.KeyRefs()
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, ref := range refs {
		used[m.IdentityFile(ref.Profile, ref.KeyName)] = true
	}
	for fp, rec := range inv.Keys {
		if affected[rec.Path] && !used[rec.Path] {
			res.PrunedKeys = append(res.PrunedKeys, basename(rec.Path))
			delete(inv.Keys, fp)
		}
	}
	// The inventory is a map, so iteration order is randomized; sort so the same
	// deletion always reports the same list.
	sort.Strings(res.PrunedKeys)
	return nil
}

func basename(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
