package mutation

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
	"github.com/simtabi/ssh-manager/src/v3/internal/version"
)

// Scope is one command a person asked for. It becomes an operation in the
// history only if it mutates: the guard opens the operation the first time the
// command takes the lock, so a read-only command records nothing, and a
// mutating one is recorded without code of its own.
type Scope struct {
	Command  string   // "host add"
	Args     []string // already redacted
	Source   string   // history.SourceCLI, SourceTUI, SourceWeb
	DryRun   bool
	Subjects []history.Subject
}

// Outcome is how a scope ended.
type Outcome struct {
	Err     error
	Aborted bool // the person declined a confirmation
}

type frame struct {
	scope Scope
	op    *history.Op
	store *history.Store
	p     paths.Paths
}

var (
	recMu  sync.Mutex
	stack  []*frame
	warned bool
	// Disabled turns recording off. The tests that are not about history set
	// it, and so does $SSH_MANAGER_HISTORY=0.
	Disabled = os.Getenv("SSH_MANAGER_HISTORY") == "0"
)

// Begin starts a scope. Scopes nest: the TUI is one scope, and every action
// chosen from its menu is its own scope inside it, recorded separately.
func Begin(s Scope) {
	recMu.Lock()
	defer recMu.Unlock()
	stack = append(stack, &frame{scope: s})
}

// End closes the innermost scope and, if it mutated, records how it ended and
// what the manifest and inventory were afterwards.
func End(o Outcome) {
	recMu.Lock()
	defer recMu.Unlock()
	if len(stack) == 0 {
		return
	}
	f := stack[len(stack)-1]
	stack = stack[:len(stack)-1]
	if f.op == nil || f.store == nil {
		return
	}
	defer func() { _ = f.store.Close() }()
	op := f.op
	switch {
	case o.Aborted:
		op.Result = history.ResultAborted
	case o.Err != nil:
		op.Result = history.ResultError
		op.Error = o.Err.Error()
	case f.scope.DryRun:
		op.Result = history.ResultDryRun
	default:
		op.Result = history.ResultOK
	}
	op.ManifestAfter = putManifest(f.store, f.p.Manifest())
	op.InventoryAfter = hashFile(f.p.Inventory())
	if err := f.store.Finish(op); err != nil {
		warn(err)
	}
}

// opening is called by the guard each time a command takes the lock. The
// first call in a scope opens its operation; later ones do nothing.
func opening(p paths.Paths) {
	if Disabled {
		return
	}
	recMu.Lock()
	defer recMu.Unlock()
	f := top()
	if f == nil || f.op != nil {
		return
	}
	openLocked(f, p)
}

func top() *frame {
	if len(stack) == 0 {
		return nil
	}
	return stack[len(stack)-1]
}

func openLocked(f *frame, p paths.Paths) {
	s, err := openStore(p)
	if err != nil {
		warn(err)
		return
	}
	op := &history.Op{
		Command:         f.scope.Command,
		Args:            f.scope.Args,
		Source:          f.scope.Source,
		Version:         version.Version,
		Subjects:        f.scope.Subjects,
		ManifestBefore:  putManifest(s, p.Manifest()),
		InventoryBefore: hashFile(p.Inventory()),
	}
	if u, err := user.Current(); err == nil {
		op.OSUser = u.Username
	}
	op.Machine, _ = os.Hostname()
	if err := s.Begin(op); err != nil {
		_ = s.Close()
		warn(err)
		return
	}
	f.op, f.store, f.p = op, s, p
}

// openStore opens the history and, the first time, imports what was on disk.
// The caller holds the advisory lock, which is what makes the import safe.
func openStore(p paths.Paths) (*history.Store, error) {
	s, err := history.Open(p.HistoryDB())
	if err != nil {
		if s != nil {
			_ = s.Close()
		}
		return nil, err
	}
	if s.NeedsBackfill() {
		if _, err := s.Backfill(SourcesFor(p)); err != nil {
			warn(fmt.Errorf("importing the earlier audit log: %w", err))
		}
	}
	return s, nil
}

// SourcesFor names what a backfill reads for the config home p.
func SourcesFor(p paths.Paths) history.Sources {
	return history.Sources{AuditLog: p.AuditLog(), Inventory: p.Inventory(),
		SnapshotsDir: p.SnapshotsDir(), Manifest: p.Manifest()}
}

// recordSnapshot attaches the guard's snapshot, or the reason there is none,
// to the open operation. A snapshot that failed used to vanish without a
// trace; it is now on the record, though the command still runs.
func recordSnapshot(snap string, snapErr error) {
	recMu.Lock()
	defer recMu.Unlock()
	f := top()
	if f == nil || f.op == nil {
		return
	}
	if snap != "" {
		f.op.Snapshot = filepath.Base(snap)
		if err := f.store.SetSnapshot(f.op.OpID, f.op.Snapshot); err != nil {
			warn(err)
		}
	}
	if snapErr != nil {
		if err := f.store.AddEvent(f.op.OpID, history.Now(), "snapshot.failed",
			[]log.Field{{Key: "error", Value: snapErr.Error()}}, f.op.Source, ""); err != nil {
			warn(err)
		}
	}
}

// sinkEvent files an audit event under the operation that raised it. An
// event outside any scope, or from another config home, is left to audit.log.
func sinkEvent(e log.Event) {
	if Disabled {
		return
	}
	recMu.Lock()
	defer recMu.Unlock()
	f := top()
	if f == nil {
		return
	}
	home := filepath.Dir(filepath.Dir(e.AuditLog))
	if f.op == nil {
		// An event means the scope changed something even if it never took
		// the lock (W6, W8); open its operation so the event has a home.
		openLocked(f, paths.Paths{ConfigDir: home})
		if f.op == nil {
			return
		}
	}
	if filepath.Clean(f.p.ConfigDir) != filepath.Clean(home) {
		return
	}
	if err := f.store.AddEvent(f.op.OpID, e.TS, e.Name, e.Fields, f.op.Source, ""); err != nil {
		warn(err)
	}
}

// InstallSink routes audit events into the history. The command layer calls it
// once at start-up; util/log cannot import the store itself.
func InstallSink() { log.SetSink(sinkEvent) }

func putManifest(s *history.Store, path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sha, err := s.PutManifest(b)
	if err != nil {
		warn(err)
	}
	return sha
}

func hashFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return history.Hash(b)
}

// warn says once per process that history is not being recorded. The command
// itself carries on: audit.log still has the events, and `sshmgr history`
// reports the shortfall.
func warn(err error) {
	if warned {
		return
	}
	warned = true
	_, _ = fmt.Fprintf(os.Stderr, "sshmgr: WARNING: the operation history was not recorded (%v); audit.log still was\n", err)
}
