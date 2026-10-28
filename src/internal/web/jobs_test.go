package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/jobs"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
)

var keyLink = regexp.MustCompile(`href="/keys/(work/[^"]+)"`)

// fixtureKey is the fixture's key, as the keys page links it.
func fixtureKey(t *testing.T, c *client) string {
	t.Helper()
	m := keyLink.FindStringSubmatch(c.get("/keys").Body.String())
	if m == nil {
		t.Fatal("the keys page links no key")
	}
	return m[1]
}

// waitJob waits for the job to finish and returns it.
func waitJob(t *testing.T, s *Server, id string) jobs.View {
	t.Helper()
	j := s.jobs.Get(id)
	if j == nil {
		t.Fatalf("no job %s", id)
	}
	deadline := time.After(10 * time.Second)
	for {
		v, changed := j.View()
		if v.State == jobs.Done || v.State == jobs.Failed || v.State == jobs.Cancelled {
			return v
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("job still %s", v.State)
		}
	}
}

// The review page says what a job does and what it is the same as; starting
// it lands on its page; its events stream its output and end with its state;
// and its failure is shown.
func TestAJobIsReviewedStartedAndStreamed(t *testing.T) {
	s, _, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	key := fixtureKey(t, c)
	if body := c.get("/keys/" + key).Body.String(); !strings.Contains(body, `value="rollback"`) {
		t.Fatalf("the key page offers no rollback:\n%s", body)
	}

	f := url.Values{"action": {"rollback"}, "key": {key}}
	rev := c.change("/jobs/review", f)
	if rev.Code != http.StatusOK || !strings.Contains(rev.Body.String(), "sshmgr rollback "+key+" --yes") {
		t.Fatalf("review: %d\n%s", rev.Code, rev.Body.String())
	}
	start := c.change("/jobs", url.Values{"action": {"rollback"}, "key": {key}})
	loc := start.Header().Get("Location")
	if start.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/jobs/") {
		t.Fatalf("start: %d to %q", start.Code, loc)
	}
	id := strings.TrimPrefix(loc, "/jobs/")
	// The fixture key was never rotated, so there is no old/ key to go back to.
	v := waitJob(t, s, id)
	if v.State != jobs.Failed || !strings.Contains(v.Err, "no /old/ predecessor") {
		t.Errorf("job = %s %q", v.State, v.Err)
	}
	if body := c.get(loc).Body.String(); !strings.Contains(body, "no /old/ predecessor") {
		t.Errorf("the job page does not show the failure:\n%s", body)
	}
	ev := c.get(loc + "/events")
	if ct := ev.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("events Content-Type %q", ct)
	}
	if !strings.Contains(ev.Body.String(), "event: state\ndata: failed\n\n") {
		t.Errorf("the stream does not end with the state:\n%s", ev.Body.String())
	}
	if len(liveOps(t, s)) == 0 {
		t.Error("the job was not recorded in the history")
	}
}

// Rotate writes the encrypted backup first, so with no recipient it stops
// before anything else, and says what is missing.
func TestRotateFromTheWebNeedsABackupFirst(t *testing.T) {
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	s, _, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	start := c.change("/jobs", url.Values{"action": {"rotate"}, "key": {fixtureKey(t, c)}})
	v := waitJob(t, s, strings.TrimPrefix(start.Header().Get("Location"), "/jobs/"))
	if v.State != jobs.Failed || !strings.Contains(v.Err, "SSH_MANAGER_AGE_RECIPIENT") {
		t.Errorf("job = %s %q", v.State, v.Err)
	}
}

// Jobs take names, never paths, and read-only serves none of them.
func TestJobsTakeNamesAndReadOnlyHasNone(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	for _, bad := range []url.Values{
		{"action": {"deploy"}, "key": {"../work/gh"}},
		{"action": {"deploy"}, "key": {"work"}},
		{"action": {"deploy"}, "key": {"work/gh"}, "target": {"../x"}},
		{"action": {"rm"}, "key": {"work/gh"}},
	} {
		if rec := c.change("/jobs/review", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d, want 400", bad, rec.Code)
		}
	}
	if rec := c.get("/jobs/nosuchjob"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown job: %d", rec.Code)
	}

	p, _ := fixtureHome(t)
	ro, err := New(Options{Engine: AppEngine{P: p}, Token: testToken, AllowedHosts: AllowedHosts("127.0.0.1", 7822, nil), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	rc := signIn(t, ro)
	for _, path := range []string{"/jobs/review", "/jobs"} {
		if rec := rc.change(path, url.Values{"action": {"deploy"}, "key": {"work/gh"}}); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("read-only %s: %d, want 405", path, rec.Code)
		}
	}
	if body := rc.get("/keys/" + fixtureKey(t, rc)).Body.String(); strings.Contains(body, "/jobs/review") {
		t.Error("read-only key page offers a job")
	}
}

// liveOps is every operation the history holds that was not imported.
func liveOps(t *testing.T, s *Server) []history.Op {
	t.Helper()
	st, err := history.Open(s.opts.Engine.Home().HistoryDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ops, err := st.Query(history.Filter{Source: history.SourceWeb})
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

// Rotating a profile's keys reviews the keys it will rotate, then writes the
// backup first, so with no recipient it stops before anything else.
func TestRotatingAProfileListsItsKeysAndNeedsABackup(t *testing.T) {
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	s, _, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	key := fixtureKey(t, c)
	rev := c.change("/jobs/review", url.Values{"action": {"rotate-keys"}, "profile": {"work"}})
	if body := rev.Body.String(); rev.Code != http.StatusOK || !strings.Contains(body, key) ||
		!strings.Contains(body, "sshmgr rotate work --yes") {
		t.Fatalf("review: %d\n%s", rev.Code, body)
	}
	start := c.change("/jobs", url.Values{"action": {"rotate-keys"}, "all": {"1"}})
	v := waitJob(t, s, strings.TrimPrefix(start.Header().Get("Location"), "/jobs/"))
	if v.State != jobs.Failed || !strings.Contains(v.Err, "SSH_MANAGER_AGE_RECIPIENT") {
		t.Errorf("job = %s %q", v.State, v.Err)
	}
	if rec := c.change("/jobs/review", url.Values{"action": {"rotate-keys"}, "profile": {"nosuch"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown profile: %d, want 400", rec.Code)
	}
}

// A bundle restore takes only a bundle named as sshmgr names them, from dist/,
// and decrypts only with the identity in the environment.
func TestBundleRestoreTakesABundleFromDistAndTheIdentityFromTheEnvironment(t *testing.T) {
	t.Setenv("SSH_MANAGER_AGE_IDENTITY_FILE", "")
	s, p, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	name := "ssh-manager-20261001-100000.age"
	for _, bad := range []string{"../manifest.json", "ssh-manager-x.age", name} {
		if rec := c.change("/jobs/review", url.Values{"action": {"bundle-restore"}, "bundle": {bad}}); rec.Code != http.StatusBadRequest {
			t.Errorf("bundle %q: %d, want 400", bad, rec.Code)
		}
	}
	if err := os.MkdirAll(p.DistDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.DistDir(), name), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if body := c.get("/snapshots").Body.String(); !strings.Contains(body, "Restore "+name) {
		t.Errorf("the snapshots page does not offer the bundle:\n%s", body)
	}
	start := c.change("/jobs", url.Values{"action": {"bundle-restore"}, "bundle": {name}})
	v := waitJob(t, s, strings.TrimPrefix(start.Header().Get("Location"), "/jobs/"))
	if v.State != jobs.Failed || !strings.Contains(v.Err, "SSH_MANAGER_AGE_IDENTITY_FILE") {
		t.Errorf("job = %s %q", v.State, v.Err)
	}
}
