// Package query is the read-only view layer over the manifest + inventory that
// backs list/view (and feeds audit), ported from src/ssh_manager/services/query.py.
// It returns structured data only; rendering lives with the caller, so the CLI and
// the future TUI format it however they like. Provider category powers --type; the
// host's free-form tags power --tag.
package query

import (
	"fmt"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/core/providers"
)

// Deployment status values.
const (
	NoKey         = "no-key"
	NeedsRedeploy = "needs-redeploy"
	Deployed      = "deployed"
)

// HostRow is one host in a list view.
type HostRow struct {
	Alias         string
	Hostname      string
	ProviderLabel string // e.g. "github/vcs" or "server"
	KeyName       string
	Status        string // no-key | needs-redeploy | deployed
	Tags          []string
}

// ProfileGroup is a profile and its (possibly filtered) host rows.
type ProfileGroup struct {
	Name  string
	Empty bool // the profile has no hosts at all
	Rows  []HostRow
}

// DeploymentRow is one recorded deployment of a key.
type DeploymentRow struct {
	Target   string
	Method   string
	Verified bool
}

// HostDetail is the resolved view of a single host (view <alias>).
type HostDetail struct {
	Profile       string
	Alias         string
	Hostname      string
	User          string
	Port          int
	IdentityFile  string
	KnownHosts    string
	ProviderLabel string
	KeyName       string
	Status        string
	Fingerprint   *string
	ExpiresOn     *string
	Tags          []string
	RawOptions    manifest.OrderedOptions
	Deployments   []DeploymentRow
	RequiresVPN   bool
	VPNName       *string
	VPNURL        *string
}

// ProfileSummary is the resolved view of a whole profile (view <profile>).
type ProfileSummary struct {
	Name     string
	KeyScope string
	Rows     []HostRow
}

// Query answers read-only questions about the manifest + inventory.
type Query struct {
	m          *manifest.Manifest
	inv        *inventory.Inventory
	categories map[string]string // provider name -> category (resolved once)
	byPath     map[string]inventory.KeyRecord
}

// New builds a Query. providersFile is the user's providers.json (may be absent;
// the embedded default catalog is used as the fallback).
func New(m *manifest.Manifest, inv *inventory.Inventory, providersFile string) *Query {
	cats := map[string]string{}
	for name, spec := range providers.AllSpecs(providersFile) {
		cats[name] = spec.Category
	}
	byPath := make(map[string]inventory.KeyRecord, len(inv.Keys))
	for _, r := range inv.Keys {
		byPath[r.Path] = r
	}
	return &Query{m: m, inv: inv, categories: cats, byPath: byPath}
}

// categoryOf mirrors query.category_of: the catalog category if known, else
// "server" (the generic-ssh fallback from registry.resolve).
func (q *Query) categoryOf(provider string) string {
	if provider != "" {
		if c, ok := q.categories[provider]; ok {
			return c
		}
	}
	return "server"
}

// Groups returns the list view, filtered by any of profile/provider/type_/tag
// (empty string means no filter on that axis).
func (q *Query) Groups(profile, provider, type_, tag string) ([]ProfileGroup, error) {
	filtered := profile != "" || provider != "" || type_ != "" || tag != ""
	var out []ProfileGroup
	for _, pname := range q.m.ProfileNames() {
		if profile != "" && pname != profile {
			continue
		}
		prof := q.m.Profiles[pname]
		var rows []HostRow
		for _, host := range prof.Hosts {
			hp := deref(host.Provider)
			if provider != "" && hp != provider {
				continue
			}
			if type_ != "" && q.categoryOf(hp) != type_ {
				continue
			}
			if tag != "" && !contains(host.Tags, tag) {
				continue
			}
			row, err := q.row(pname, host)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		if len(rows) > 0 || (!filtered && len(prof.Hosts) == 0) {
			out = append(out, ProfileGroup{Name: pname, Empty: len(prof.Hosts) == 0, Rows: rows})
		}
	}
	return out, nil
}

// Detail returns a *ProfileSummary when selector names a profile, else a
// *HostDetail when it matches a host alias, else an error.
func (q *Query) Detail(selector string) (any, error) {
	if prof, ok := q.m.Profiles[selector]; ok {
		var rows []HostRow
		for _, h := range prof.Hosts {
			row, err := q.row(selector, h)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		return &ProfileSummary{Name: selector, KeyScope: prof.KeyScope, Rows: rows}, nil
	}
	for _, pname := range q.m.ProfileNames() {
		for _, host := range q.m.Profiles[pname].Hosts {
			if host.Alias == selector {
				return q.hostDetail(pname, host)
			}
		}
	}
	return nil, fmt.Errorf("no profile or host alias matches %q", selector)
}

func (q *Query) providerLabel(host manifest.Host) string {
	provider := deref(host.Provider)
	cat := q.categoryOf(provider)
	if provider != "" {
		return provider + "/" + cat
	}
	return cat
}

func (q *Query) row(pname string, host manifest.Host) (HostRow, error) {
	kname, err := q.m.ResolvedKeyName(pname, host)
	if err != nil {
		return HostRow{}, err
	}
	rec, ok := q.byPath[q.m.IdentityFile(pname, kname)]
	return HostRow{
		Alias: host.Alias, Hostname: host.Hostname,
		ProviderLabel: q.providerLabel(host), KeyName: kname,
		Status: status(rec, ok), Tags: tagsOf(host),
	}, nil
}

func (q *Query) hostDetail(pname string, host manifest.Host) (*HostDetail, error) {
	kname, err := q.m.ResolvedKeyName(pname, host)
	if err != nil {
		return nil, err
	}
	ident := q.m.IdentityFile(pname, kname)
	rec, ok := q.byPath[ident]
	var fp *string
	for f, r := range q.inv.Keys {
		if r.Path == ident {
			fpCopy := f
			fp = &fpCopy
			break
		}
	}
	var deps []DeploymentRow
	var expiresOn *string
	if ok {
		for _, d := range rec.Deployments {
			deps = append(deps, DeploymentRow{Target: d.Target, Method: d.Method, Verified: d.Verified})
		}
		expiresOn = rec.ExpiresOn
	}
	return &HostDetail{
		Profile: pname, Alias: host.Alias, Hostname: host.Hostname, User: host.User,
		Port: host.Port, IdentityFile: ident, KnownHosts: q.m.KnownHostsFile(pname),
		ProviderLabel: q.providerLabel(host), KeyName: kname, Status: status(rec, ok),
		Fingerprint: fp, ExpiresOn: expiresOn, Tags: tagsOf(host), RawOptions: host.RawOptions,
		Deployments: deps, RequiresVPN: host.RequiresVPN, VPNName: host.VPNName, VPNURL: host.VPNURL,
	}, nil
}

func status(rec inventory.KeyRecord, found bool) string {
	if !found {
		return NoKey
	}
	if rec.NeedsRedeploy() {
		return NeedsRedeploy
	}
	return Deployed
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func tagsOf(h manifest.Host) []string {
	out := make([]string, len(h.Tags))
	copy(out, h.Tags)
	return out
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
