package web

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/expiry"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/renderer"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/doctor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/notifier"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/overview"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/query"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// ErrNotFound is a name that matches nothing in the manifest, the snapshots
// or the history. Handlers turn it into a 404.
var ErrNotFound = errors.New("not found")

// Engine is everything the pages read. Every argument is a name - a profile,
// a host alias, a key, a snapshot id, an operation id - resolved here against
// what exists, never a filesystem path. AppEngine is the real one; tests pass
// their own.
type Engine interface {
	Home() paths.Paths
	Overview(now time.Time) (Overview, error)
	Profiles() ([]ProfileView, error)
	Hosts() ([]query.ProfileGroup, error)
	Host(alias string) (HostView, error)
	Keys() ([]keysvc.Row, error)
	Key(ref string) (KeyView, error)
	Snapshots() ([]SnapshotView, error)
	SnapshotDiff(id, against string) (SnapshotDiff, error)
	History(f history.Filter) ([]history.Op, error)
	Op(id string) (OpView, error)
	Doctor() (doctor.Report, error)
	Audit(now time.Time) (AuditView, error)
	Export(name string, includeGit bool) (string, error)

	// Preview runs a change on a private copy of the home; Apply makes it
	// if a fresh preview under the lock still has the confirmed hash.
	Preview(ch change.Change) (change.Plan, error)
	Apply(ch change.Change, hash string) (change.Plan, change.Result, error)
}

// Overview is the first page: the banner's rows, and the counts behind them.
type Overview struct {
	Rows     []overview.Row
	Problems int
	Profiles int
	Hosts    int
	Keys     int
	Expiry   []expiry.Status
	Recent   []history.Op
	DevRoot  string
}

// ProfileView is one profile in the profiles list.
type ProfileView struct {
	Name, Category, KeyScope, KeyStore string
	Hosts, Keys                        int
}

// HostView is one host: the manifest entry and what it resolves to.
type HostView struct {
	Detail *query.HostDetail
	Block  string
	Pins   []knownhosts.Entry
	Token  string
	VM     bool // a VM host, which can have a Docker context
}

// KeyView is one key: its row, its detail, and its expiry.
type KeyView struct {
	Detail keysvc.Detail
	Expiry *expiry.Status
	Ops    []history.Op
}

// SnapshotView is one snapshot in the list.
type SnapshotView struct {
	ID         string
	Taken      time.Time
	Size       int64
	KeyBearing bool
}

// SnapshotDiff compares a snapshot with the tree now, or with another snapshot.
type SnapshotDiff struct {
	ID, Against string // Against "" means the current ~/.ssh
	Files       []FileDiff
	Refused     string // why the snapshot was not opened
}

// FileDiff is one file's change.
type FileDiff struct {
	Path  string
	State string // added | removed | changed
	Lines []history.DiffLine
}

// OpView is one operation and its manifest diff.
type OpView struct {
	Op       history.Op
	Diff     []history.DiffLine
	DiffNote string
}

// AuditView is the audit report, as data.
type AuditView struct {
	Keys   []AuditKey
	Expiry []expiry.Status
	Recent []history.Op
}

// AuditKey is one inventory record and where it is deployed.
type AuditKey struct {
	Path, Fingerprint, Status string
	Deployments               []inventory.Deployment
}

// AppEngine reads one sshmgr home through the same services the CLI uses.
// It loads the manifest and inventory on every call: the CLI may change them
// at any moment, and a page must show what is there now.
type AppEngine struct {
	P paths.Paths
	// Retain is how many snapshots a change keeps, as the CLI's
	// $SSH_MANAGER_SNAPSHOT_RETAIN; zero means 10.
	Retain int
}

// Preview shows what ch would do, without doing it.
func (e AppEngine) Preview(ch change.Change) (change.Plan, error) { return change.Preview(e.P, ch) }

// Apply makes ch if it would still do what was confirmed.
func (e AppEngine) Apply(ch change.Change, hash string) (change.Plan, change.Result, error) {
	retain := e.Retain
	if retain < 1 {
		retain = 10
	}
	return change.Apply(e.P, ch, hash, retain, history.SourceWeb)
}

// Home is the paths this engine reads.
func (e AppEngine) Home() paths.Paths { return e.P }

func (e AppEngine) manifest() (*manifest.Manifest, error) {
	m, err := manifest.Load(e.P.Manifest())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no manifest at %s yet; run `sshmgr init` first", e.P.Manifest())
		}
		return nil, err
	}
	return m, nil
}

func (e AppEngine) inventory() *inventory.Inventory {
	inv, err := inventory.Load(e.P.Inventory())
	if err != nil {
		return &inventory.Inventory{Keys: map[string]inventory.KeyRecord{}}
	}
	return inv
}

// Overview reads the banner's rows through overview.Rows, the same function
// the TUI prints, so the two never disagree.
func (e AppEngine) Overview(now time.Time) (Overview, error) {
	m, _ := manifest.Load(e.P.Manifest())
	ov := Overview{Rows: overview.Rows(e.P, m, now), DevRoot: e.P.DevRoot}
	for _, r := range ov.Rows {
		if r.Fix != "" {
			ov.Problems++
		}
	}
	if m != nil {
		ov.Profiles = len(m.ProfileNames())
		for _, n := range m.ProfileNames() {
			ov.Hosts += len(m.Profiles[n].Hosts)
		}
		if refs, err := m.KeyRefs(); err == nil {
			ov.Keys = len(refs)
		}
		if states, err := notifier.New(e.P, m).States(now); err == nil {
			for _, s := range states {
				if s.NeedsAttention() {
					ov.Expiry = append(ov.Expiry, s)
				}
			}
		}
	}
	ov.Recent, _ = e.History(history.Filter{Limit: 5})
	return ov, nil
}

// Profiles lists every profile with its counts.
func (e AppEngine) Profiles() ([]ProfileView, error) {
	m, err := e.manifest()
	if err != nil {
		return nil, err
	}
	refs, _ := m.KeyRefs()
	keys := map[string]int{}
	for _, r := range refs {
		keys[r.Profile]++
	}
	var out []ProfileView
	for _, n := range m.ProfileNames() {
		p := m.Profiles[n]
		store := p.KeyStore
		if store == "" {
			store = "disk"
		}
		out = append(out, ProfileView{Name: n, Category: p.Category, KeyScope: p.KeyScope, KeyStore: store,
			Hosts: len(p.Hosts), Keys: keys[n]})
	}
	return out, nil
}

// Hosts lists every host, grouped by profile, as `sshmgr list` does.
func (e AppEngine) Hosts() ([]query.ProfileGroup, error) {
	m, err := e.manifest()
	if err != nil {
		return nil, err
	}
	return query.New(m, e.inventory(), e.P.Providers()).Groups("", "", "", "")
}

// Host is one host as `sshmgr show <alias>` reports it.
func (e AppEngine) Host(alias string) (HostView, error) {
	m, err := e.manifest()
	if err != nil {
		return HostView{}, err
	}
	for _, pname := range m.ProfileNames() {
		for _, h := range m.Profiles[pname].Hosts {
			if h.Alias != alias {
				continue
			}
			d, err := query.New(m, e.inventory(), e.P.Providers()).Detail(alias)
			if err != nil {
				return HostView{}, err
			}
			hd, ok := d.(*query.HostDetail)
			if !ok {
				// A profile and a host share the name; Detail prefers the profile.
				hd = &query.HostDetail{Profile: pname, Alias: h.Alias, Hostname: h.Hostname, User: h.User, Port: h.Port}
			}
			v := HostView{Detail: hd, Token: knownHostsToken(h), VM: h.VM != nil}
			if block, err := renderer.RenderHostBlockFor(m, pname, h); err == nil {
				v.Block = block
			}
			v.Pins = knownhosts.New(e.P.SSHDir).EntriesFor(v.Token)
			return v, nil
		}
	}
	return HostView{}, ErrNotFound
}

func knownHostsToken(h manifest.Host) string {
	if h.Port == 0 || h.Port == 22 {
		return h.Hostname
	}
	return fmt.Sprintf("[%s]:%d", h.Hostname, h.Port)
}

// Keys lists every key, as `sshmgr key list` does.
func (e AppEngine) Keys() ([]keysvc.Row, error) {
	m, err := e.manifest()
	if err != nil {
		return nil, err
	}
	return keysvc.New(m, e.inventory(), e.P.SSHDir).Rows("")
}

// Key is one key by its profile/key reference.
func (e AppEngine) Key(ref string) (KeyView, error) {
	m, err := e.manifest()
	if err != nil {
		return KeyView{}, err
	}
	refs, err := m.KeyRefs()
	if err != nil {
		return KeyView{}, err
	}
	for _, r := range refs {
		if r.String() != ref {
			continue
		}
		d, err := keysvc.New(m, e.inventory(), e.P.SSHDir).Detail(r)
		if err != nil {
			return KeyView{}, err
		}
		v := KeyView{Detail: d}
		if states, err := notifier.New(e.P, m).States(time.Now()); err == nil {
			for i := range states {
				if states[i].Profile == r.Profile && states[i].KeyName == r.KeyName {
					v.Expiry = &states[i]
				}
			}
		}
		v.Ops, _ = e.History(history.Filter{Key: r.KeyName, Profile: r.Profile, Limit: 20})
		return v, nil
	}
	return KeyView{}, ErrNotFound
}

// Snapshots lists the snapshots, newest first.
func (e AppEngine) Snapshots() ([]SnapshotView, error) {
	list := snapshots.List(e.P.SnapshotsDir())
	out := make([]SnapshotView, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		s := list[i]
		v := SnapshotView{ID: filepath.Base(s), KeyBearing: snapshots.HoldsKeyMaterial(s)}
		if fi, err := os.Stat(s); err == nil {
			v.Size, v.Taken = fi.Size(), fi.ModTime()
		}
		out = append(out, v)
	}
	return out, nil
}

// snapshotPath resolves a snapshot id to its file, only if it is one of the
// snapshots List returns. An id is never joined onto a path unchecked.
func (e AppEngine) snapshotPath(id string) (string, bool) {
	for _, s := range snapshots.List(e.P.SnapshotsDir()) {
		if filepath.Base(s) == id {
			return s, true
		}
	}
	return "", false
}

// SnapshotDiff compares snapshot id with another snapshot, or with ~/.ssh as
// it is now when against is "". A snapshot holding key material is refused,
// not opened: showing a diff would put the key on the page.
func (e AppEngine) SnapshotDiff(id, against string) (SnapshotDiff, error) {
	path, ok := e.snapshotPath(id)
	if !ok {
		return SnapshotDiff{}, ErrNotFound
	}
	d := SnapshotDiff{ID: id, Against: against}
	old, err := snapshots.Files(path)
	if errors.Is(err, snapshots.ErrHoldsKeyMaterial) {
		d.Refused = err.Error()
		return d, nil
	}
	if err != nil {
		return d, err
	}
	var cur map[string]string
	if against == "" {
		cur, err = snapshots.CurrentFiles(e.P.SSHDir)
	} else {
		other, ok := e.snapshotPath(against)
		if !ok {
			return d, ErrNotFound
		}
		cur, err = snapshots.Files(other)
		if errors.Is(err, snapshots.ErrHoldsKeyMaterial) {
			d.Refused = against + ": " + err.Error()
			return d, nil
		}
	}
	if err != nil {
		return d, err
	}
	d.Files = diffTrees(old, cur)
	return d, nil
}

func diffTrees(old, cur map[string]string) []FileDiff {
	names := map[string]bool{}
	for k := range old {
		names[k] = true
	}
	for k := range cur {
		names[k] = true
	}
	sorted := make([]string, 0, len(names))
	for k := range names {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []FileDiff
	for _, n := range sorted {
		a, inOld := old[n]
		b, inCur := cur[n]
		switch {
		case inOld && !inCur:
			out = append(out, FileDiff{Path: n, State: "removed", Lines: history.Diff(a, "", 3)})
		case !inOld && inCur:
			out = append(out, FileDiff{Path: n, State: "added", Lines: history.Diff("", b, 3)})
		case a != b:
			out = append(out, FileDiff{Path: n, State: "changed", Lines: history.Diff(a, b, 3)})
		}
	}
	return out
}

// History reads the operation history without writing to it: a page view
// must not create the database or run the first import.
func (e AppEngine) History(f history.Filter) ([]history.Op, error) {
	s, err := e.openHistory()
	if err != nil || s == nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	return s.Query(f)
}

func (e AppEngine) openHistory() (*history.Store, error) {
	if _, err := os.Stat(e.P.HistoryDB()); err != nil {
		return nil, nil
	}
	s, err := history.Open(e.P.HistoryDB())
	if errors.Is(err, history.ErrNewerSchema) {
		return s, nil
	}
	return s, err
}

// Op is one operation and the manifest diff across it.
func (e AppEngine) Op(id string) (OpView, error) {
	s, err := e.openHistory()
	if err != nil {
		return OpView{}, err
	}
	if s == nil {
		return OpView{}, ErrNotFound
	}
	defer func() { _ = s.Close() }()
	op, ok, err := s.Get(id)
	if err != nil {
		return OpView{}, err
	}
	if !ok {
		return OpView{}, ErrNotFound
	}
	v := OpView{Op: op}
	switch {
	case op.ManifestBefore == "" || op.ManifestAfter == "":
		v.DiffNote = "No manifest was recorded for this operation."
	case op.ManifestBefore == op.ManifestAfter:
		v.DiffNote = "The manifest did not change."
	default:
		before, _ := s.Manifest(op.ManifestBefore)
		after, _ := s.Manifest(op.ManifestAfter)
		v.Diff = history.Diff(string(before), string(after), 3)
	}
	return v, nil
}

// Doctor runs the same checks as `sshmgr doctor`, without --fix.
func (e AppEngine) Doctor() (doctor.Report, error) {
	m, _ := manifest.Load(e.P.Manifest())
	return doctor.New(e.P, m, platform.EmitUseKeychain()).Run(false), nil
}

// Audit is `sshmgr audit` as data: deployments, expiry, recent activity.
func (e AppEngine) Audit(now time.Time) (AuditView, error) {
	m, err := e.manifest()
	if err != nil {
		return AuditView{}, err
	}
	inv := e.inventory()
	var v AuditView
	fps := make([]string, 0, len(inv.Keys))
	for fp := range inv.Keys {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool {
		a, b := inv.Keys[fps[i]], inv.Keys[fps[j]]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return fps[i] < fps[j]
	})
	for _, fp := range fps {
		rec := inv.Keys[fp]
		status := "deployed"
		if rec.NeedsRedeploy() {
			status = "needs-redeploy"
		}
		v.Keys = append(v.Keys, AuditKey{Path: rec.Path, Fingerprint: fp, Status: status, Deployments: rec.Deployments})
	}
	v.Expiry, _ = notifier.New(e.P, m).States(now)
	v.Recent, _ = e.History(history.Filter{Limit: 10})
	return v, nil
}

// splitRef parses "profile/key" from a URL.
func splitRef(s string) (string, bool) {
	prof, key, ok := strings.Cut(s, "/")
	return s, ok && prof != "" && key != "" && !strings.Contains(key, "/")
}

// Exports a page can download. Each is rendered the way `sshmgr config export
// --flat` and `sshmgr termius export` render it, and none is written anywhere.
const (
	ExportFlat    = "ssh_config"
	ExportTermius = "termius-hosts.csv"
)

// Export renders one of the exports for download.
func (e AppEngine) Export(name string, includeGit bool) (string, error) {
	m, err := e.manifest()
	if err != nil {
		return "", err
	}
	ep := renderer.ExportPathsFor(e.P.SSHDir)
	switch name {
	case ExportFlat:
		return renderer.RenderFlatConfig(m, ep, platform.EmitUseKeychain())
	case ExportTermius:
		exp, err := renderer.RenderTermiusCSV(m, ep, renderer.TermiusOptions{IncludeGit: includeGit})
		if err != nil {
			return "", err
		}
		return exp.CSV, nil
	}
	return "", ErrNotFound
}
