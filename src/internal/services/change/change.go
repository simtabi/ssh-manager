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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

	// Mints marks a change that makes a new key. Its preview mints a
	// throwaway key in the copy, which apply cannot reproduce, so public key
	// blobs and fingerprints are left out of the hash: the confirmation
	// binds to everything else the change writes, and to which keys it makes.
	Mints bool

	// NoSnapshot skips the ~/.ssh snapshot before the change, for one that
	// manages the snapshots themselves and would otherwise prune its own.
	NoSnapshot bool

	// Effects lists what the change does outside the files a preview copies
	// - snapshots it removes, modes it fixes - as lines for the preview to
	// show. They are part of the hash, so they cannot change unseen either.
	Effects func(p paths.Paths) ([]string, error)

	// OnApply is the part of a change that a copy cannot hold - a Docker
	// context, a desktop notification, an encrypted backup of private keys.
	// It runs on apply only, under the lock, after the snapshot and before
	// Run. A preview never runs it, so a change with OnApply must say what it
	// does in Effects; Preview refuses one that does not.
	OnApply func(p paths.Paths, out io.Writer) error
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
	Effects []string
	Hidden  []string // files the copy holds no content for that the change removes or creates
	Output  string
	Err     string // the change would fail, with this message
	Mints   bool   // the keys it shows are throwaway; apply mints new ones
	// NoSnapshot is set when apply takes no snapshot of ~/.ssh first.
	NoSnapshot bool
	Hash       string
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
	plan := Plan{Command: ch.Command, Args: ch.Args, Mints: ch.Mints, NoSnapshot: ch.NoSnapshot}
	if ch.Effects != nil {
		if plan.Effects, err = ch.Effects(p); err != nil {
			plan.Err = err.Error()
		}
	}
	if ch.OnApply != nil && ch.Effects == nil {
		return Plan{}, fmt.Errorf("%s acts outside the copy and does not say how: it needs Effects", ch.Command)
	}
	unseenBefore := unseen(shadow)
	// An effect that cannot be worked out is not something to run blind.
	if plan.Err == "" {
		if err := ch.Run(shadow, &out); err != nil {
			plan.Err = err.Error()
		}
	}
	plan.Output = strings.ReplaceAll(out.String(), shadow.ConfigDir, p.ConfigDir)
	plan.Output = strings.ReplaceAll(plan.Output, shadow.SSHDir, p.SSHDir)
	after, err := capture(shadow)
	if err != nil {
		return Plan{}, err
	}
	plan.Files = diffTrees(before, after)
	plan.Hidden = hiddenChanges(unseenBefore, unseen(shadow))
	plan.Hash = hashPlan(ch, before, after, plan)
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
		if ch.NoSnapshot {
			mutation.LockForMutation(p)
		} else if snap := mutation.SnapshotBeforeMutation(p, retain); snap != "" {
			res.Snapshot = filepath.Base(snap)
		}
		var out bytes.Buffer
		if ch.OnApply != nil {
			if err := ch.OnApply(p, &out); err != nil {
				res.Output = out.String()
				return err
			}
		}
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
	// The layout matters as much as the contents: a command decides whether
	// a key exists by looking for its file. So every directory is recreated,
	// every copied file keeps its modification time (a recorded key is dated
	// from its .pub), and every file the copy does not take - a private key,
	// above all - is stood in for by an empty placeholder at the same path.
	// The placeholder says the file is there; it holds nothing of it.
	_ = filepath.Walk(p.SSHDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(p.SSHDir, path)
		if err != nil {
			return nil
		}
		dst := filepath.Join(shadow.SSHDir, rel)
		switch {
		case fi.IsDir():
			_ = os.MkdirAll(dst, 0o700)
		case !fi.Mode().IsRegular():
		case snapshots.Archivable(fi.Name()):
			_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
		default:
			if f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
				_ = f.Close()
				_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
			}
		}
		return nil
	})
	if err := os.MkdirAll(shadow.SSHDir, 0o700); err != nil {
		cleanup()
		return paths.Paths{}, nil, err
	}
	return shadow, cleanup, nil
}

// unseen lists the files under the copy's ~/.ssh that it holds no content
// for: placeholders, and anything a change made that a snapshot would not
// take, such as a minted private key.
func unseen(shadow paths.Paths) map[string]bool {
	out := map[string]bool{}
	_ = filepath.Walk(shadow.SSHDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || !fi.Mode().IsRegular() || snapshots.Archivable(fi.Name()) {
			return nil
		}
		if rel, err := filepath.Rel(shadow.SSHDir, path); err == nil {
			out[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	return out
}

// hiddenChanges says which of those files the change removed or created, so a
// preview shows a private key being deleted or moved even though it cannot
// show the key.
func hiddenChanges(before, after map[string]bool) []string {
	var out []string
	for rel := range before {
		if !after[rel] {
			out = append(out, "removes ~/.ssh/"+rel)
		}
	}
	for rel := range after {
		if !before[rel] {
			out = append(out, "creates ~/.ssh/"+rel)
		}
	}
	sort.Strings(out)
	return out
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
func hashPlan(ch Change, before, after map[string]string, plan Plan) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", ch.Command, strings.Join(ch.Args, "\x00"), plan.Err)
	for _, e := range plan.Effects {
		_, _ = fmt.Fprintf(h, "effect\x00%s\x00", e)
	}
	for _, e := range plan.Hidden {
		_, _ = fmt.Fprintf(h, "hidden\x00%s\x00", e)
	}
	keys := make([]string, 0, len(before))
	for k := range before {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", k, history.Hash([]byte(before[k])))
	}
	if ch.Mints {
		// Not the diff: the inventory is keyed by fingerprint, so a fresh key's
		// record lands somewhere different every time and moves the diff's
		// shape, not just its bytes. The state it leads to, in canonical form,
		// is the same however the throwaway key happened to come out.
		names := make([]string, 0, len(after))
		for k := range after {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			_, _ = fmt.Fprintf(h, "after\x00%s\x00%s\x00", k, canonical(k, after[k]))
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	for _, f := range plan.Files {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", f.Path, f.State, history.FormatDiff(f.Lines))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// canonical is a file's content with what differs between two mints of the
// same keys taken out: key blobs and fingerprints, and for the inventory, the
// fingerprint-keyed order of its records.
func canonical(name, body string) string {
	blank := func(s string) string {
		return volatileFingerprints.ReplaceAllString(volatileKeys.ReplaceAllString(s, "<key>"), "<fingerprint>")
	}
	if name != "config/inventory.json" {
		return blank(body)
	}
	var inv struct {
		Version int                        `json:"version"`
		Keys    map[string]json.RawMessage `json:"keys"`
	}
	if json.Unmarshal([]byte(body), &inv) != nil {
		return blank(body)
	}
	recs := make([]string, 0, len(inv.Keys))
	for _, r := range inv.Keys {
		recs = append(recs, blank(string(r)))
	}
	sort.Strings(recs)
	return fmt.Sprintf("version %d\n%s", inv.Version, strings.Join(recs, "\n"))
}

// volatileKeys and volatileFingerprints match what differs between two mints
// of the same key: the public key blob and its fingerprint. Inventory records
// are keyed by fingerprint, so the key match covers those lines too.
var (
	volatileKeys         = regexp.MustCompile(`(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) [A-Za-z0-9+/=]{16,}`)
	volatileFingerprints = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]{20,}`)
)
