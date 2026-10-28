// Package change previews a change before it is made, and makes it only if
// what it would do has not moved since it was previewed.
//
// A preview runs the change for real, against a private copy of the home:
// the config files, and from ~/.ssh only the files a snapshot may hold
// (config, known_hosts, public keys). It then diffs what the copy became
// against what is there now, so the preview is not a description of the
// change but the change itself, made somewhere harmless. No private key is
// ever copied.
//
// Apply takes the lock, previews again under it, and runs the change on the
// real home only if the new preview hashes the same as the one the person
// confirmed. Anything that moved in between - a CLI command, another browser
// tab - is reported with the new preview instead of being overwritten. The
// lock is held only for that, never while a person reads.
package change

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// ErrStale reports a confirmation made against a preview that no longer
// matches what the change would do.
var ErrStale = fmt.Errorf("the change would now do something different from what you confirmed: %w", mutation.ErrDeclined)

// Change is one change a person can ask for. Run makes it against p, the way
// the CLI command does after its guard; it never takes the lock or snapshots,
// which Apply does around it.
type Change struct {
	Command  string // "host add"
	Args     []string
	Subjects []history.Subject
	Run      func(p paths.Paths, out io.Writer) error
}

// FileDiff is one file the change touches. Path is relative to the home it
// belongs to, prefixed "~/.ssh/" or "config/" so the two trees read apart.
type FileDiff struct {
	Path  string
	State string // added | removed | changed
	Lines []history.DiffLine
}

// Plan is a preview: what the change would write, what it would say, and a
// hash binding the two to the state they were computed from.
type Plan struct {
	Command string
	Args    []string
	Files   []FileDiff
	Output  string
	Err     string // the change would fail, with this message
	Hash    string
}

// Result is a change that was made.
type Result struct {
	Output   string
	OpID     string
	Snapshot string
}

// configFiles are the config-home files a change may read or write. .env and
// the age identity are left out: no change here needs them, and a copy of a
// secret is a second place it can leak from.
var configFiles = []string{"manifest.json", "inventory.json", "providers.json"}

// Preview runs ch against a private copy of p and reports what it would do.
// It writes nothing outside the copy and records nothing in the history.
func Preview(p paths.Paths, ch Change) (Plan, error) {
	applyMu.Lock()
	defer applyMu.Unlock()
	return preview(p, ch)
}

func preview(p paths.Paths, ch Change) (Plan, error) {
	defer mutation.Suspend()()
	before, err := capture(p)
	if err != nil {
		return Plan{}, err
	}
	shadow, cleanup, err := copyHome(p)
	if err != nil {
		return Plan{}, err
	}
	defer cleanup()

	var out bytes.Buffer
	plan := Plan{Command: ch.Command, Args: ch.Args}
	if err := ch.Run(shadow, &out); err != nil {
		plan.Err = err.Error()
	}
	plan.Output = strings.ReplaceAll(out.String(), shadow.ConfigDir, p.ConfigDir)
	plan.Output = strings.ReplaceAll(plan.Output, shadow.SSHDir, p.SSHDir)
	after, err := capture(shadow)
	if err != nil {
		return Plan{}, err
	}
	plan.Files = diffTrees(before, after)
	plan.Hash = hashPlan(ch, before, plan)
	return plan, nil
}

// applyMu allows one preview or change at a time in this process. The
// advisory lock serializes processes; within a server, two requests would
// otherwise share one lock and interleave, and a preview's suspension of the
// history would swallow a real change's events.
var applyMu sync.Mutex

// Apply makes ch on p if a fresh preview under the lock still hashes to hash.
// On ErrStale it returns that fresh preview, for the person to confirm again.
func Apply(p paths.Paths, ch Change, hash string, retain int, source string) (Plan, Result, error) {
	applyMu.Lock()
	defer applyMu.Unlock()
	scope := mutation.Scope{Command: ch.Command, Args: ch.Args, Source: source,
		Subjects: ch.Subjects, OpID: history.NewOpID()}
	var plan Plan
	var res Result
	err := mutation.Scoped(p, scope, func() error {
		fresh, err := preview(p, ch)
		if err != nil {
			return err
		}
		if fresh.Hash != hash {
			plan = fresh
			return ErrStale
		}
		if fresh.Err != "" {
			return errors.New(fresh.Err)
		}
		if snap := mutation.SnapshotBeforeMutation(p, retain); snap != "" {
			res.Snapshot = filepath.Base(snap)
		}
		var out bytes.Buffer
		err = ch.Run(p, &out)
		res.Output = out.String()
		return err
	})
	if err == nil || !errors.Is(err, ErrStale) {
		res.OpID = scope.OpID
	}
	return plan, res, err
}

// capture reads every file a change may touch, keyed by its display path.
func capture(p paths.Paths) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range configFiles {
		b, err := os.ReadFile(filepath.Join(p.ConfigDir, name))
		if err == nil {
			out["config/"+name] = string(b)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	ssh, err := snapshots.CurrentFiles(p.SSHDir)
	if err != nil {
		return nil, err
	}
	for rel, body := range ssh {
		out["~/.ssh/"+rel] = body
	}
	return out, nil
}

// copyHome makes the private copy a preview runs in: owner-only, removed
// afterwards, holding no private key.
func copyHome(p paths.Paths) (paths.Paths, func(), error) {
	dir, err := os.MkdirTemp("", "sshmgr-preview-")
	if err != nil {
		return paths.Paths{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	shadow := paths.Paths{SSHDir: filepath.Join(dir, "ssh"), ConfigDir: filepath.Join(dir, "config")}
	files, err := capture(p)
	if err != nil {
		cleanup()
		return paths.Paths{}, nil, err
	}
	for key, body := range files {
		var dst string
		if rel, ok := strings.CutPrefix(key, "config/"); ok {
			dst = filepath.Join(shadow.ConfigDir, rel)
		} else {
			dst = filepath.Join(shadow.SSHDir, filepath.FromSlash(strings.TrimPrefix(key, "~/.ssh/")))
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			cleanup()
			return paths.Paths{}, nil, err
		}
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			cleanup()
			return paths.Paths{}, nil, err
		}
	}
	// The directory layout matters to commands that look for a profile's
	// directory; recreate it, without any of the files in it.
	_ = filepath.Walk(p.SSHDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || !fi.IsDir() {
			return nil
		}
		if rel, err := filepath.Rel(p.SSHDir, path); err == nil {
			_ = os.MkdirAll(filepath.Join(shadow.SSHDir, rel), 0o700)
		}
		return nil
	})
	if err := os.MkdirAll(shadow.SSHDir, 0o700); err != nil {
		cleanup()
		return paths.Paths{}, nil, err
	}
	return shadow, cleanup, nil
}

// DiffTrees compares two captured trees, file by file, in path order.
func DiffTrees(before, after map[string]string) []FileDiff { return diffTrees(before, after) }

func diffTrees(before, after map[string]string) []FileDiff {
	names := map[string]bool{}
	for k := range before {
		names[k] = true
	}
	for k := range after {
		names[k] = true
	}
	sorted := make([]string, 0, len(names))
	for k := range names {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []FileDiff
	for _, n := range sorted {
		a, inA := before[n]
		b, inB := after[n]
		switch {
		case inA && !inB:
			out = append(out, FileDiff{Path: n, State: "removed", Lines: history.Diff(a, "", 3)})
		case !inA && inB:
			out = append(out, FileDiff{Path: n, State: "added", Lines: history.Diff("", b, 3)})
		case a != b:
			out = append(out, FileDiff{Path: n, State: "changed", Lines: history.Diff(a, b, 3)})
		}
	}
	return out
}

// hashPlan binds a preview to the change and the state it was computed
// from. The output is left out: it names paths that differ between the copy
// and the home, and it describes the change rather than being it.
func hashPlan(ch Change, before map[string]string, plan Plan) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", ch.Command, strings.Join(ch.Args, "\x00"), plan.Err)
	keys := make([]string, 0, len(before))
	for k := range before {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", k, history.Hash([]byte(before[k])))
	}
	for _, f := range plan.Files {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", f.Path, f.State, history.FormatDiff(f.Lines))
	}
	return hex.EncodeToString(h.Sum(nil))
}
