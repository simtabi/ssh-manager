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
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/log"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// DeleteResult summarizes a profile/host deletion.
type DeleteResult struct {
	Removed    string
	Revoked    []string
	PrunedKeys []string
}

// Format renders the human-readable deletion summary.
func (r DeleteResult) Format() string {
	lines := []string{"deleted " + r.Removed}
	if len(r.Revoked) > 0 {
		lines = append(lines, "  revoked from: "+strings.Join(r.Revoked, ", "))
	}
	if len(r.PrunedKeys) > 0 {
		lines = append(lines, "  pruned inventory: "+strings.Join(r.PrunedKeys, ", "))
	}
	lines = append(lines, "  run `sshmgr reconcile` to re-render; local key files (if any) "+
		"are left in place (doctor flags them as orphaned).")
	return strings.Join(lines, "\n")
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
	affected := map[string]bool{}
	for _, host := range m.Profiles[name].Hosts {
		kn, err := m.ResolvedKeyName(name, host)
		if err != nil {
			return DeleteResult{}, err
		}
		affected[m.IdentityFile(name, kn)] = true
		e.revokeHost(m, inv, name, host, revoke, &res)
	}
	m.DeleteProfile(name)
	e.pruneIdents(m, inv, affected, &res)
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
	e.pruneIdents(m, inv, affected, &res)
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

// pruneIdents drops inventory records for the affected key paths that no surviving
// manifest host references any more.
func (e *Editor) pruneIdents(m *manifest.Manifest, inv *inventory.Inventory, affected map[string]bool, res *DeleteResult) {
	used := map[string]bool{}
	for _, pname := range m.ProfileNames() {
		for _, h := range m.Profiles[pname].Hosts {
			if kn, err := m.ResolvedKeyName(pname, h); err == nil {
				used[m.IdentityFile(pname, kn)] = true
			}
		}
	}
	for fp, rec := range inv.Keys {
		if affected[rec.Path] && !used[rec.Path] {
			res.PrunedKeys = append(res.PrunedKeys, basename(rec.Path))
			delete(inv.Keys, fp)
		}
	}
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
