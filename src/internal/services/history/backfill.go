package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
)

// MetaBackfillDone is set once the first open has imported what was on disk.
const MetaBackfillDone = "backfill_done"

// Sources is what a backfill reads. Any of them may be missing.
type Sources struct {
	AuditLog     string // audit.log; its rotated .1 is read too, first
	Inventory    string
	SnapshotsDir string
	Manifest     string
}

// BackfillResult counts what a backfill imported.
type BackfillResult struct {
	Events    int
	Skipped   int // unreadable audit lines
	Manifests int
}

// NeedsBackfill reports a store that has not yet imported what was on disk.
func (s *Store) NeedsBackfill() bool { return !s.readOnly && s.Meta(MetaBackfillDone) == "" }

// Backfill imports the history that existed before the store did: every
// audit.log event, the creation and deployment dates inventory.json records,
// the snapshots on disk, and the current manifest. Each becomes an operation
// of source "backfill", so the timeline starts where the tool's records do.
//
// It runs in one transaction and marks itself done in the same one, so a
// backfill that fails leaves nothing behind and the next open tries again.
// Every event carries a dedupe key besides, so importing the same line twice
// records it once.
func (s *Store) Backfill(src Sources) (BackfillResult, error) {
	var res BackfillResult
	if err := s.writable(); err != nil {
		return res, err
	}
	var recs []record
	for _, f := range []string{src.AuditLog + ".1", src.AuditLog} {
		got, skipped, err := readAudit(f)
		if err != nil {
			return res, err
		}
		recs = append(recs, got...)
		res.Skipped += skipped
	}
	recs = append(recs, inventoryRecords(src.Inventory)...)
	recs = append(recs, snapshotRecords(src.SnapshotsDir)...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].ts < recs[j].ts })

	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	seen := map[string]int{}
	for _, r := range recs {
		body := fieldsJSON(r.fields)
		// Two identical lines in one second are two events, so the key counts
		// occurrences; it stays deterministic, which is what makes it a dedupe key.
		base := r.ts + "|" + r.event + "|" + body
		seen[base]++
		dedupe := Hash([]byte(fmt.Sprintf("%s|%d", base, seen[base])))
		opID := dedupe[:32]
		if _, err := tx.Exec(`insert or ignore into ops(op_id, started_at, finished_at, command, args, source, result)
			values(?,?,?,?,?,?,?)`, opID, r.ts, r.ts, strings.ReplaceAll(r.event, ".", " "), "[]", SourceBackfill, ResultOK); err != nil {
			return res, err
		}
		ins, err := tx.Exec(`insert or ignore into events(op_id, ts, event, fields, source, dedupe) values(?,?,?,?,?,?)`,
			opID, r.ts, r.event, body, SourceBackfill, dedupe)
		if err != nil {
			return res, err
		}
		if n, _ := ins.RowsAffected(); n == 0 {
			continue
		}
		id, _ := ins.LastInsertId()
		for _, sub := range dedupeSubjects(SubjectsOf(r.fields)) {
			if _, err := tx.Exec(`insert into subjects(event_id, op_id, kind, name) values(?,?,?,?)`, id, opID, sub.Kind, sub.Name); err != nil {
				return res, err
			}
		}
		res.Events++
	}
	if body, err := os.ReadFile(src.Manifest); err == nil {
		if _, err := tx.Exec(`insert or ignore into manifests(sha, captured_at, body) values(?,?,?)`, Hash(body), Now(), body); err != nil {
			return res, err
		}
		res.Manifests++
	}
	if _, err := tx.Exec(`insert into meta(key, value) values(?,?) on conflict(key) do update set value=excluded.value`,
		MetaBackfillDone, Now()); err != nil {
		return res, err
	}
	return res, tx.Commit()
}

type record struct {
	ts, event string
	fields    []log.Field
}

// readAudit parses one audit log. A line that is not an audit record is
// counted and skipped rather than failing the import: the log is append-only
// and best-effort, so a torn last line after a crash is expected.
func readAudit(path string) ([]record, int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	var out []record
	skipped := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		r, ok := ParseAuditLine(line)
		if !ok {
			skipped++
			continue
		}
		out = append(out, r.record())
	}
	return out, skipped, sc.Err()
}

// AuditLine is one parsed audit.log line, with its fields in written order.
type AuditLine struct {
	TS, Event string
	Fields    []log.Field
}

func (a AuditLine) record() record { return record{ts: a.TS, event: a.Event, fields: a.Fields} }

// ParseAuditLine reads one audit.log line, keeping the order its fields were
// written in, which a map would lose.
func ParseAuditLine(line []byte) (AuditLine, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return AuditLine{}, false
	}
	var a AuditLine
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return AuditLine{}, false
		}
		key, ok := kt.(string)
		if !ok {
			return AuditLine{}, false
		}
		var v any
		if err := dec.Decode(&v); err != nil {
			return AuditLine{}, false
		}
		switch key {
		case "ts":
			a.TS, _ = v.(string)
		case "event":
			a.Event, _ = v.(string)
		default:
			a.Fields = append(a.Fields, log.Field{Key: key, Value: v})
		}
	}
	if _, err := dec.Token(); err != nil {
		return AuditLine{}, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return AuditLine{}, false
	}
	if a.TS == "" || a.Event == "" {
		return AuditLine{}, false
	}
	return a, true
}

// inventoryRecords turns the dates inventory.json keeps into events: when each
// key was made, and when each deployment was recorded.
func inventoryRecords(path string) []record {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var inv struct {
		Keys map[string]struct {
			Profile     string  `json:"profile"`
			Path        string  `json:"path"`
			Created     *string `json:"created"`
			Deployments []struct {
				Target string  `json:"target"`
				Method string  `json:"method"`
				Date   *string `json:"date"`
			} `json:"deployments"`
		} `json:"keys"`
	}
	if json.Unmarshal(b, &inv) != nil {
		return nil
	}
	fps := make([]string, 0, len(inv.Keys))
	for fp := range inv.Keys {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	var out []record
	for _, fp := range fps {
		k := inv.Keys[fp]
		name := strings.TrimSuffix(filepath.Base(filepath.FromSlash(k.Path)), ".pub")
		if ts := normalizeDate(k.Created); ts != "" {
			out = append(out, record{ts: ts, event: "key.created", fields: []log.Field{
				{Key: "profile", Value: k.Profile}, {Key: "key", Value: name}, {Key: "fingerprint", Value: fp}}})
		}
		for _, d := range k.Deployments {
			if ts := normalizeDate(d.Date); ts != "" {
				out = append(out, record{ts: ts, event: "deploy", fields: []log.Field{
					{Key: "profile", Value: k.Profile}, {Key: "key", Value: name},
					{Key: "target", Value: d.Target}, {Key: "method", Value: d.Method}}})
			}
		}
	}
	return out
}

var snapshotName = regexp.MustCompile(`^ssh-(\d{8}-\d{6})(?:[.-]\d+)?\.tar\.gz$`)

// snapshotRecords dates each snapshot from the local-time stamp in its name.
func snapshotRecords(dir string) []record {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []record
	for _, e := range entries {
		m := snapshotName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		t, err := time.ParseInLocation("20060102-150405", m[1], time.Local)
		if err != nil {
			continue
		}
		out = append(out, record{ts: t.UTC().Format(TimeFormat), event: "snapshot",
			fields: []log.Field{{Key: "snapshot", Value: e.Name()}}})
	}
	return out
}

// normalizeDate accepts the forms inventory.json has used - a date, or an
// RFC 3339 time - and returns the store's format, "" when it is neither.
func normalizeDate(s *string) string {
	if s == nil || *s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return t.UTC().Format(TimeFormat)
		}
	}
	return ""
}

// String summarizes a backfill for the one line `history` prints after it.
func (r BackfillResult) String() string {
	s := fmt.Sprintf("imported %d earlier event(s) into the history", r.Events)
	if r.Skipped > 0 {
		s += fmt.Sprintf(" (%d unreadable audit line(s) skipped)", r.Skipped)
	}
	return s
}
