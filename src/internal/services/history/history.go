// Package history is the operation history: a SQLite database in the config
// home's log directory that records every command that changed something, the
// audit events it raised, and the manifest before and after.
//
// audit.log stays the record of what happened, and is written first and
// regardless. This store indexes it so it can be filtered by host, profile or
// key and outlive the log's two-generation rotation, and adds what the log
// never held: which command ran, how it ended, and what the manifest was on
// either side of it.
//
// Rows are written only by a process holding the advisory lock, so the store
// relies on that and not on SQLite for ordering. Reads take no lock; WAL lets
// them run beside a writer.
package history

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Sources an operation can come from.
const (
	SourceCLI      = "cli"
	SourceTUI      = "tui"
	SourceWeb      = "web"
	SourceBackfill = "backfill"
)

// Results an operation can end with.
const (
	ResultOK      = "ok"
	ResultError   = "error"
	ResultAborted = "aborted"
	ResultDryRun  = "dry-run"
)

// Subject kinds, for filtering.
const (
	KindProfile = "profile"
	KindHost    = "host"
	KindKey     = "key"
	KindTarget  = "target"
)

// TimeFormat is how every timestamp in the store is written: UTC, to the
// second, the form audit.log already uses, so the two sort together.
const TimeFormat = "2006-01-02T15:04:05Z"

// ErrNewerSchema reports a database written by a newer sshmgr. It is opened
// read-only rather than migrated down, and never written.
var ErrNewerSchema = errors.New("the history database was written by a newer sshmgr; it is open read-only")

// Store is an open history database.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
}

// Subject is one name an operation or event is about.
type Subject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Op is one recorded operation, with the events it raised.
type Op struct {
	OpID            string    `json:"op_id"`
	StartedAt       string    `json:"started_at"`
	FinishedAt      string    `json:"finished_at,omitempty"`
	Command         string    `json:"command"`
	Args            []string  `json:"args"`
	Source          string    `json:"source"`
	OSUser          string    `json:"os_user,omitempty"`
	Machine         string    `json:"machine,omitempty"`
	Version         string    `json:"version,omitempty"`
	Result          string    `json:"result,omitempty"`
	Error           string    `json:"error,omitempty"`
	Snapshot        string    `json:"snapshot,omitempty"`
	ManifestBefore  string    `json:"manifest_before,omitempty"`
	ManifestAfter   string    `json:"manifest_after,omitempty"`
	InventoryBefore string    `json:"inventory_before,omitempty"`
	InventoryAfter  string    `json:"inventory_after,omitempty"`
	Subjects        []Subject `json:"subjects,omitempty"`
	Events          []Event   `json:"events"`
}

// Event is one recorded audit event.
type Event struct {
	TS     string          `json:"ts"`
	Event  string          `json:"event"`
	Fields json.RawMessage `json:"fields"`
	Source string          `json:"source"`
}

// Open opens the database at path, creating it owner-only and applying any
// migrations it is missing. A database from a newer sshmgr opens read-only and
// Open returns it together with ErrNewerSchema.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Created 0600 before SQLite sees it, so there is no window in which a fresh
	// database is readable by other accounts: it maps every host and key.
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		_ = f.Close()
	} else {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	// One connection: every write is already serialized by the advisory lock,
	// and a single connection keeps the pragmas and the WAL handle in one place.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		if errors.Is(err, ErrNewerSchema) {
			s.readOnly = true
			return s, err
		}
		_ = db.Close()
		return nil, err
	}
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Chmod(path+side, 0o600)
	}
	return s, nil
}

func dsn(path string) string {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "busy_timeout(5000)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path is the database file.
func (s *Store) Path() string { return s.path }

// ReadOnly reports a database this binary must not write.
func (s *Store) ReadOnly() bool { return s.readOnly }

func (s *Store) migrate() error {
	var have int
	if err := s.db.QueryRow("pragma user_version").Scan(&have); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	if have > len(names) {
		return ErrNewerSchema
	}
	for i, name := range names {
		v := i + 1
		if v <= have {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("history migration %s: %w", filepath.Base(name), err)
		}
		// pragma takes no bound parameter; v is an integer from this loop.
		if _, err := tx.Exec("pragma user_version = " + strconv.Itoa(v)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writable() error {
	if s.readOnly {
		return ErrNewerSchema
	}
	return nil
}

// NewOpID returns a fresh operation id: 16 random bytes, hex.
func NewOpID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Now is the current time in the store's format.
func Now() string { return time.Now().UTC().Format(TimeFormat) }

// Begin records the start of an operation. op.OpID and op.StartedAt are filled
// in when empty.
func (s *Store) Begin(op *Op) error {
	if err := s.writable(); err != nil {
		return err
	}
	if op.OpID == "" {
		op.OpID = NewOpID()
	}
	if op.StartedAt == "" {
		op.StartedAt = Now()
	}
	args, _ := json.Marshal(nonNil(op.Args))
	_, err := s.db.Exec(`insert into ops(op_id, started_at, command, args, source, os_user, machine, version,
		manifest_before, inventory_before, snapshot) values(?,?,?,?,?,?,?,?,?,?,?)`,
		op.OpID, op.StartedAt, op.Command, string(args), op.Source, null(op.OSUser), null(op.Machine),
		null(op.Version), null(op.ManifestBefore), null(op.InventoryBefore), null(op.Snapshot))
	if err != nil {
		return err
	}
	return s.addSubjects(op.OpID, 0, op.Subjects)
}

// Finish closes an operation with its result.
func (s *Store) Finish(op *Op) error {
	if err := s.writable(); err != nil {
		return err
	}
	if op.FinishedAt == "" {
		op.FinishedAt = Now()
	}
	_, err := s.db.Exec(`update ops set finished_at=?, result=?, error=?, snapshot=coalesce(?, snapshot),
		manifest_after=?, inventory_after=? where op_id=?`,
		op.FinishedAt, null(op.Result), null(op.Error), null(op.Snapshot),
		null(op.ManifestAfter), null(op.InventoryAfter), op.OpID)
	return err
}

// SetSnapshot records the snapshot an operation took.
func (s *Store) SetSnapshot(opID, snapshot string) error {
	if err := s.writable(); err != nil {
		return err
	}
	_, err := s.db.Exec(`update ops set snapshot=? where op_id=?`, null(snapshot), opID)
	return err
}

// AddEvent records one audit event. opID "" records it on no operation.
// dedupe "" is a live event; a backfilled one passes a key so that running the
// backfill twice records it once.
func (s *Store) AddEvent(opID, ts, name string, fields []log.Field, source, dedupe string) error {
	if err := s.writable(); err != nil {
		return err
	}
	body := fieldsJSON(fields)
	res, err := s.db.Exec(`insert or ignore into events(op_id, ts, event, fields, source, dedupe) values(?,?,?,?,?,?)`,
		null(opID), ts, name, body, source, null(dedupe))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	return s.addSubjects(opID, id, SubjectsOf(fields))
}

func (s *Store) addSubjects(opID string, eventID int64, subs []Subject) error {
	for _, sub := range dedupeSubjects(subs) {
		if _, err := s.db.Exec(`insert into subjects(event_id, op_id, kind, name) values(?,?,?,?)`,
			nullInt(eventID), null(opID), sub.Kind, sub.Name); err != nil {
			return err
		}
	}
	return nil
}

// PutManifest stores a manifest body by its SHA-256 and returns the hash. A
// body already stored is not stored again.
func (s *Store) PutManifest(body []byte) (string, error) {
	sha := Hash(body)
	if err := s.writable(); err != nil {
		return sha, err
	}
	_, err := s.db.Exec(`insert or ignore into manifests(sha, captured_at, body) values(?,?,?)`, sha, Now(), body)
	return sha, err
}

// Manifest returns a stored manifest body, or nil when the hash is unknown.
func (s *Store) Manifest(sha string) ([]byte, error) {
	var body []byte
	err := s.db.QueryRow(`select body from manifests where sha=?`, sha).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return body, err
}

// Hash is the store's content hash: SHA-256, hex.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Meta reads a meta value, "" when unset.
func (s *Store) Meta(key string) string {
	var v string
	_ = s.db.QueryRow(`select value from meta where key=?`, key).Scan(&v)
	return v
}

// SetMeta writes a meta value.
func (s *Store) SetMeta(key, value string) error {
	if err := s.writable(); err != nil {
		return err
	}
	_, err := s.db.Exec(`insert into meta(key, value) values(?,?) on conflict(key) do update set value=excluded.value`, key, value)
	return err
}

// Filter narrows a query. Zero values match everything.
type Filter struct {
	Host, Profile, Key string
	Since, Until       string // inclusive, in TimeFormat or a prefix of it ("2026-10-27")
	Command            string // exact, or a prefix ending in a space-free word ("host" matches "host add")
	Source             string
	Limit              int

	opID string // exact operation, for Get
}

// Query returns the operations matching f, newest first, each with its events.
func (s *Store) Query(f Filter) ([]Op, error) {
	var where []string
	var args []any
	for kind, name := range map[string]string{KindHost: f.Host, KindProfile: f.Profile, KindKey: f.Key} {
		if name == "" {
			continue
		}
		where = append(where, `exists (select 1 from subjects s where s.op_id = ops.op_id and s.kind = ? and s.name = ?)`)
		args = append(args, kind, name)
	}
	if f.Since != "" {
		where = append(where, `started_at >= ?`)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		// A date-only bound covers the whole day: "…Z" sorts after every time in it.
		where = append(where, `started_at <= ?`)
		args = append(args, f.Until+"￿")
	}
	if f.Command != "" {
		where = append(where, `(command = ? or command like ? escape '\')`)
		args = append(args, f.Command, likeEscape(f.Command)+" %")
	}
	if f.Source != "" {
		where = append(where, `source = ?`)
		args = append(args, f.Source)
	}
	if f.opID != "" {
		where = append(where, `op_id = ?`)
		args = append(args, f.opID)
	}
	q := `select op_id, started_at, coalesce(finished_at,''), command, args, source, coalesce(os_user,''),
		coalesce(machine,''), coalesce(version,''), coalesce(result,''), coalesce(error,''), coalesce(snapshot,''),
		coalesce(manifest_before,''), coalesce(manifest_after,''), coalesce(inventory_before,''),
		coalesce(inventory_after,'') from ops`
	if len(where) > 0 {
		q += " where " + strings.Join(where, " and ")
	}
	q += " order by started_at desc, id desc"
	if f.Limit > 0 {
		q += " limit " + strconv.Itoa(f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	var ops []Op
	for rows.Next() {
		var o Op
		var a string
		if err := rows.Scan(&o.OpID, &o.StartedAt, &o.FinishedAt, &o.Command, &a, &o.Source, &o.OSUser,
			&o.Machine, &o.Version, &o.Result, &o.Error, &o.Snapshot, &o.ManifestBefore, &o.ManifestAfter,
			&o.InventoryBefore, &o.InventoryAfter); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(a), &o.Args)
		o.Args = nonNil(o.Args)
		ops = append(ops, o)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range ops {
		if err := s.fill(&ops[i]); err != nil {
			return nil, err
		}
	}
	return ops, nil
}

// Get returns one operation by id, or by a unique prefix of it (as git does
// with commits). ok is false when nothing matches.
func (s *Store) Get(id string) (Op, bool, error) {
	rows, err := s.db.Query(`select op_id from ops where op_id like ? escape '\' limit 2`, likeEscape(id)+"%")
	if err != nil {
		return Op{}, false, err
	}
	var ids []string
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		ids = append(ids, v)
	}
	_ = rows.Close()
	if len(ids) != 1 {
		if len(ids) > 1 {
			return Op{}, false, fmt.Errorf("%q matches more than one operation; give more of the id", id)
		}
		return Op{}, false, nil
	}
	all, err := s.Query(Filter{opID: ids[0]})
	if err != nil || len(all) == 0 {
		return Op{}, false, err
	}
	return all[0], true, nil
}

func (s *Store) fill(o *Op) error {
	rows, err := s.db.Query(`select ts, event, fields, source from events where op_id=? order by ts, id`, o.OpID)
	if err != nil {
		return err
	}
	o.Events = []Event{}
	for rows.Next() {
		var e Event
		var fields string
		if err := rows.Scan(&e.TS, &e.Event, &fields, &e.Source); err != nil {
			_ = rows.Close()
			return err
		}
		e.Fields = json.RawMessage(fields)
		o.Events = append(o.Events, e)
	}
	_ = rows.Close()
	srows, err := s.db.Query(`select distinct kind, name from subjects where op_id=? order by kind, name`, o.OpID)
	if err != nil {
		return err
	}
	for srows.Next() {
		var sub Subject
		_ = srows.Scan(&sub.Kind, &sub.Name)
		o.Subjects = append(o.Subjects, sub)
	}
	_ = srows.Close()
	return nil
}

// Counts reports how many operations and events the store holds.
func (s *Store) Counts() (ops, events int) {
	_ = s.db.QueryRow(`select count(*) from ops`).Scan(&ops)
	_ = s.db.QueryRow(`select count(*) from events`).Scan(&events)
	return ops, events
}

// SubjectsOf names what an audit event is about, from the fields sshmgr's
// events use for it.
func SubjectsOf(fields []log.Field) []Subject {
	var out []Subject
	for _, f := range fields {
		kind := ""
		switch f.Key {
		case "profile":
			kind = KindProfile
		case "alias", "host":
			kind = KindHost
		case "key":
			kind = KindKey
		case "target":
			kind = KindTarget
		default:
			continue
		}
		if name, ok := f.Value.(string); ok && name != "" {
			out = append(out, Subject{Kind: kind, Name: name})
		}
	}
	return out
}

func dedupeSubjects(in []Subject) []Subject {
	seen := map[Subject]bool{}
	var out []Subject
	for _, s := range in {
		if s.Name == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// fieldsJSON renders fields as the object audit.log holds for them, in order.
func fieldsJSON(fields []log.Field) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.Key)
		v, _ := json.Marshal(f.Value)
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.String()
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// LiveAuditEvents counts the audit events recorded live - not imported, and
// not the store's own snapshot.failed notes - strictly after since.
func (s *Store) LiveAuditEvents(since string) int {
	var n int
	_ = s.db.QueryRow(`select count(*) from events where source != ? and event != 'snapshot.failed' and ts > ?`,
		SourceBackfill, since).Scan(&n)
	return n
}
