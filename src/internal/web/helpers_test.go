package web

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

const testHost = "127.0.0.1:7822"

// testToken is generated per run: a fixed literal in a credential position is
// what secret scanners report.
var testToken = NewToken()

// privateMarker stands in for a private key. A page that ever shows it has put
// key material in front of a browser.
const privateMarker = "-----BEGIN OPENSSH PRIVATE KEY-----"

// fixtureHome is a small but complete sshmgr home: one profile with a host and
// a key, an inventory record, a rendered config, two snapshots (one clean, one
// from before private keys were excluded), and one recorded operation.
func fixtureHome(t *testing.T) (paths.Paths, string) {
	t.Helper()
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(p.Manifest(), `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`)
	write(p.Inventory(), `{"version":1,"keys":{}}`)
	write(filepath.Join(p.SSHDir, "config"), "Host gh\n  HostName github.com\n")
	// A private key on disk, which no page may ever show.
	write(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519"), privateMarker+"\nsecret\n")

	snap := filepath.Join(p.SnapshotsDir(), "ssh-20261001-100000.tar.gz")
	writeTar(t, snap, map[string]string{".ssh/config": "Host gh\n  HostName old.github.com\n"})
	legacy := filepath.Join(p.SnapshotsDir(), "ssh-20260901-100000.tar.gz")
	writeTar(t, legacy, map[string]string{".ssh/config": "Host gh\n", ".ssh/id_ed25519": privateMarker + "\nsecret\n"})
	old := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	_ = os.Chtimes(legacy, old, old)

	s, err := history.Open(p.HistoryDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.SetMeta(history.MetaBackfillDone, history.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := s.PutManifest([]byte("{\n  \"a\": 1\n}\n"))
	after, _ := s.PutManifest([]byte("{\n  \"a\": 2\n}\n"))
	op := &history.Op{Command: "host add", Source: history.SourceCLI, Args: []string{"work", "gh"},
		ManifestBefore: before, Subjects: []history.Subject{{Kind: history.KindHost, Name: "gh"}}}
	if err := s.Begin(op); err != nil {
		t.Fatal(err)
	}
	_ = s.AddEvent(op.OpID, history.Now(), "host.add", []log.Field{{Key: "profile", Value: "work"}, {Key: "alias", Value: "gh"}}, history.SourceCLI, "")
	op.Result, op.ManifestAfter = history.ResultOK, after
	if err := s.Finish(op); err != nil {
		t.Fatal(err)
	}
	return p, op.OpID
}

func writeTar(t *testing.T, path string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()
}

func newTestServer(t *testing.T) (*Server, paths.Paths, string) {
	t.Helper()
	p, opID := fixtureHome(t)
	s, err := New(Options{
		Engine:       AppEngine{P: p},
		Token:        testToken,
		AllowedHosts: AllowedHosts("127.0.0.1", 7822, nil),
		Version:      "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, p, opID
}

func do(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	return rec
}

type client struct {
	s      *Server
	cookie *http.Cookie
}

// signIn exchanges the launch token for a session cookie, as a browser does.
func signIn(t *testing.T, s *Server) *client {
	t.Helper()
	rec := do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/?token="+testToken, nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("token exchange: %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return &client{s: s, cookie: c}
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func (c *client) get(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://"+testHost+path, nil)
	r.AddCookie(c.cookie)
	return do(c.s, r)
}

func (c *client) post(path string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://"+testHost+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+testHost)
	r.AddCookie(c.cookie)
	return do(c.s, r)
}
