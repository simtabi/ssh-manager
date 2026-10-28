package history

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "log", "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenCreatesAnOwnerOnlyDatabaseAtTheCurrentSchema(t *testing.T) {
	s := open(t)
	var v int
	if err := s.db.QueryRow("pragma user_version").Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version = %d, %v; want 1", v, err)
	}
	var mode string
	_ = s.db.QueryRow("pragma journal_mode").Scan(&mode)
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(s.Path())
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("history.db is %v, want 0600: it maps every host and key", fi.Mode().Perm())
		}
	}
	// Reopening applies nothing twice.
	path := s.Path()
	_ = s.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = again.Close()
}

// A database from a newer sshmgr is opened, read and never written: migrating
// it down would destroy what the newer binary recorded.
func TestANewerSchemaOpensReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("pragma user_version = 99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(path)
	if !errors.Is(err, ErrNewerSchema) || s == nil {
		t.Fatalf("Open = %v, %v; want the store and ErrNewerSchema", s, err)
	}
	defer func() { _ = s.Close() }()
	if !s.ReadOnly() {
		t.Error("a newer schema should open read-only")
	}
	if err := s.Begin(&Op{Command: "x", Source: SourceCLI}); !errors.Is(err, ErrNewerSchema) {
		t.Errorf("writing a newer schema: %v, want ErrNewerSchema", err)
	}
	if _, err := s.Query(Filter{}); err != nil {
		t.Errorf("reading a newer schema: %v", err)
	}
}

func recordOp(t *testing.T, s *Store, command string, subjects []Subject, events ...string) *Op {
	t.Helper()
	op := &Op{Command: command, Source: SourceCLI, Args: []string{"a"}, Subjects: subjects}
	if err := s.Begin(op); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := s.AddEvent(op.OpID, Now(), e, []log.Field{{Key: "profile", Value: "work"}, {Key: "alias", Value: "gh"}}, SourceCLI, ""); err != nil {
			t.Fatal(err)
		}
	}
	op.Result = ResultOK
	if err := s.Finish(op); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestQueryFiltersBySubjectCommandAndSource(t *testing.T) {
	s := open(t)
	hostAdd := recordOp(t, s, "host add", nil, "host.add")
	recordOp(t, s, "profile add", []Subject{{KindProfile, "home"}})
	recordOp(t, s, "deploy", []Subject{{KindKey, "id_work"}, {KindTarget, "web1"}})

	cases := []struct {
		name string
		f    Filter
		want []string
	}{
		{"everything, newest first", Filter{}, []string{"deploy", "profile add", "host add"}},
		{"host from an event's alias", Filter{Host: "gh"}, []string{"host add"}},
		{"profile from an event", Filter{Profile: "work"}, []string{"host add"}},
		{"profile from the scope", Filter{Profile: "home"}, []string{"profile add"}},
		{"key", Filter{Key: "id_work"}, []string{"deploy"}},
		{"command group", Filter{Command: "host"}, []string{"host add"}},
		{"exact command", Filter{Command: "profile add"}, []string{"profile add"}},
		{"a group is a whole word", Filter{Command: "hos"}, nil},
		{"source", Filter{Source: SourceTUI}, nil},
		{"limit", Filter{Limit: 1}, []string{"deploy"}},
		{"since tomorrow", Filter{Since: "2999-01-01"}, nil},
		{"until a past day", Filter{Until: "2000-01-01"}, nil},
	}
	for _, c := range cases {
		ops, err := s.Query(c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		for _, o := range ops {
			got = append(got, o.Command)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}

	got, ok, err := s.Get(hostAdd.OpID[:6])
	if err != nil || !ok {
		t.Fatalf("Get by prefix: %v %v", ok, err)
	}
	if len(got.Events) != 1 || got.Events[0].Event != "host.add" {
		t.Errorf("events = %+v", got.Events)
	}
	var fields map[string]string
	if err := json.Unmarshal(got.Events[0].Fields, &fields); err != nil || fields["alias"] != "gh" {
		t.Errorf("fields = %s (%v)", got.Events[0].Fields, err)
	}
	if _, ok, _ := s.Get("ffffffffffff"); ok {
		t.Error("an unknown id should not be found")
	}
}

func TestManifestsAreStoredOnceByContent(t *testing.T) {
	s := open(t)
	a, err := s.PutManifest([]byte(`{"version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.PutManifest([]byte(`{"version":1}`))
	if a != b {
		t.Fatal("the same body hashed differently")
	}
	var n int
	_ = s.db.QueryRow("select count(*) from manifests").Scan(&n)
	if n != 1 {
		t.Errorf("stored %d copies of one manifest", n)
	}
	body, _ := s.Manifest(a)
	if string(body) != `{"version":1}` {
		t.Errorf("body = %q", body)
	}
	if body, _ := s.Manifest("nope"); body != nil {
		t.Error("an unknown hash should return nil")
	}
}

func TestParseAuditLineKeepsTheFieldOrder(t *testing.T) {
	a, ok := ParseAuditLine([]byte(`{"ts":"2026-10-01T10:00:00Z","event":"host.add","zebra":"z","alpha":1,"profile":"w"}`))
	if !ok {
		t.Fatal("a valid line did not parse")
	}
	var keys []string
	for _, f := range a.Fields {
		keys = append(keys, f.Key)
	}
	if strings.Join(keys, ",") != "zebra,alpha,profile" {
		t.Errorf("fields came back as %v", keys)
	}
	if got := fieldsJSON(a.Fields); got != `{"zebra":"z","alpha":1,"profile":"w"}` {
		t.Errorf("re-encoded as %s", got)
	}
	for _, bad := range []string{``, `not json`, `{"ts":"x"}`, `{"event":"x"}`, `{"ts":"x","event":"y"} trailing`, `[1]`} {
		if _, ok := ParseAuditLine([]byte(bad)); ok {
			t.Errorf("%q parsed as an audit line", bad)
		}
	}
}

func writeHome(t *testing.T) Sources {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	snaps := filepath.Join(dir, "snapshots")
	for _, d := range []string{logDir, snaps} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	src := Sources{AuditLog: filepath.Join(logDir, "audit.log"), Inventory: filepath.Join(dir, "inventory.json"),
		SnapshotsDir: snaps, Manifest: filepath.Join(dir, "manifest.json")}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(src.AuditLog+".1", `{"ts":"2026-09-01T09:00:00Z","event":"profile.add","profile":"work"}`+"\n")
	write(src.AuditLog, `{"ts":"2026-10-01T09:00:00Z","event":"host.add","profile":"work","alias":"gh"}`+"\n"+
		`{"ts":"2026-10-01T09:00:00Z","event":"host.add","profile":"work","alias":"gh"}`+"\n"+
		`{"ts":"2026-10-02T09:00:00Z","event":"torn`+"\n")
	write(src.Inventory, `{"version":1,"keys":{"SHA256:abc":{"profile":"work","path":"~/.ssh/profiles/work/id_work",
		"type":"ed25519","comment":null,"created":"2026-08-15","rotate_after_days":365,"expires_on":null,
		"deployments":[{"target":"web1","method":"ssh-copy-id","date":"2026-08-16","verified":true}]}}}`)
	write(filepath.Join(snaps, "ssh-20260920-101500.tar.gz"), "x")
	write(filepath.Join(snaps, "ssh-20260920-101500-1.tar.gz"), "x")
	write(filepath.Join(snaps, "not-a-snapshot.txt"), "x")
	write(src.Manifest, `{"version":1}`)
	return src
}

// The backfill is what makes the history useful on the day it is installed,
// so it has to import every source, in time order, exactly once.
func TestBackfillImportsWhatWasOnDiskOnce(t *testing.T) {
	s := open(t)
	src := writeHome(t)
	if !s.NeedsBackfill() {
		t.Fatal("a fresh store should need a backfill")
	}
	res, err := s.Backfill(src)
	if err != nil {
		t.Fatal(err)
	}
	// profile.add, host.add twice (two lines are two events), key.created,
	// deploy, and two snapshots; the torn line is skipped.
	if res.Events != 7 || res.Skipped != 1 || res.Manifests != 1 {
		t.Errorf("backfill = %+v, want 7 events, 1 skipped, 1 manifest", res)
	}
	if s.NeedsBackfill() {
		t.Error("the backfill did not mark itself done")
	}
	ops, err := s.Query(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 7 {
		t.Fatalf("%d operations, want 7", len(ops))
	}
	if first := ops[len(ops)-1]; first.Command != "key created" || first.StartedAt != "2026-08-15T00:00:00Z" {
		t.Errorf("oldest = %s at %s, want key created on 2026-08-15", first.Command, first.StartedAt)
	}
	if got, _ := s.Query(Filter{Key: "id_work"}); len(got) != 2 {
		t.Errorf("--key id_work found %d, want the key's creation and its deployment", len(got))
	}
	for _, o := range ops {
		if o.Source != SourceBackfill {
			t.Errorf("%s has source %q", o.Command, o.Source)
		}
	}

	// Again: the dedupe keys hold, nothing is added.
	if _, err := s.Backfill(src); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Query(Filter{}); len(again) != 7 {
		t.Errorf("a second backfill left %d operations, want 7", len(again))
	}
}

func TestBackfillOfAnEmptyHomeIsDone(t *testing.T) {
	s := open(t)
	dir := t.TempDir()
	res, err := s.Backfill(Sources{AuditLog: filepath.Join(dir, "log", "audit.log"),
		Inventory: filepath.Join(dir, "inventory.json"), SnapshotsDir: filepath.Join(dir, "snapshots"),
		Manifest: filepath.Join(dir, "manifest.json")})
	if err != nil || res.Events != 0 {
		t.Fatalf("backfill of nothing = %+v, %v", res, err)
	}
	if s.NeedsBackfill() {
		t.Error("an empty home still counts as backfilled")
	}
}

func TestDiffShowsOnlyChangesWithContext(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n"
	got := FormatDiff(Diff(a, b, 1))
	want := " 4\n-5\n+five\n 6\n"
	if got != want {
		t.Errorf("diff =\n%s\nwant\n%s", got, want)
	}
	if Diff(a, a, 3) != nil {
		t.Error("identical text should diff to nothing")
	}
	two := FormatDiff(Diff("a\nb\nc\nd\ne\nf\ng\n", "A\nb\nc\nd\ne\nf\nG\n", 1))
	if !strings.Contains(two, "@@") {
		t.Errorf("separate changes should be separate hunks:\n%s", two)
	}
}

// The store must not become a second place secrets live. The manifest and
// inventory hold none, and args are redacted by the caller; this proves the
// store adds nothing of its own, by scanning every text column it writes.
func TestTheStoreHoldsNoKeyMaterial(t *testing.T) {
	s := open(t)
	src := writeHome(t)
	if _, err := s.Backfill(src); err != nil {
		t.Fatal(err)
	}
	recordOp(t, s, "host add", nil, "host.add")
	_ = s.Close()
	db, err := sql.Open("sqlite", dsn(s.Path()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`select args from ops union all select fields from events union all
		select cast(body as text) from manifests union all select value from meta`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		n++
		for _, marker := range []string{"PRIVATE KEY", "BEGIN OPENSSH", "AGE-SECRET-KEY"} {
			if strings.Contains(v, marker) {
				t.Errorf("the store holds %q: %s", marker, v)
			}
		}
	}
	if n < 5 {
		t.Fatalf("scanned %d values; the scan is not reaching the data", n)
	}
}
