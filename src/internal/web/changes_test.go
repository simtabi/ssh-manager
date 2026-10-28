package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
)

func (c *client) change(path string, f url.Values) *httptest.ResponseRecorder {
	sess := c.s.sessions.get(c.cookie.Value)
	f.Set(csrfField, sess.csrf)
	return c.post(path, f.Encode())
}

var hashField = regexp.MustCompile(`name="hash" value="([0-9a-f]{64})"`)

func addHost(alias string) url.Values {
	return url.Values{"action": {"host-add"}, "profile": {"work"}, "alias": {alias},
		"hostname": {alias + ".example"}, "user": {"deploy"}, "port": {"22"}, "tags": {"a, b"}}
}

// The whole flow: preview shows the diff and writes nothing; confirming makes
// the change, records it as a web operation, and links to it.
func TestPreviewThenApplyMakesTheChange(t *testing.T) {
	s, p, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	before, _ := os.ReadFile(p.Manifest())

	rec := c.change("/changes/preview", addHost("db"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "config/manifest.json") || !strings.Contains(body, "sshmgr host add work db") {
		t.Fatalf("preview: %d\n%s", rec.Code, body)
	}
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(before) {
		t.Fatal("the preview wrote the manifest")
	}
	m := hashField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the preview has no confirm hash:\n%s", body)
	}

	f := addHost("db")
	f.Set("hash", m[1])
	rec = c.change("/changes/apply", f)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Made the change") {
		t.Fatalf("apply: %d\n%s", rec.Code, body)
	}
	if after, _ := os.ReadFile(p.Manifest()); !strings.Contains(string(after), `"db.example"`) {
		t.Error("the change was not made")
	}
	if mutation.Held() {
		t.Error("the server kept the lock after a change")
	}
	op := regexp.MustCompile(`href="/history/([0-9a-f]{32})"`).FindStringSubmatch(body)
	if op == nil {
		t.Fatalf("the done page does not link to the operation:\n%s", body)
	}
	if rec := c.get("/history/" + op[1]); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web") {
		t.Errorf("the operation page: %d", rec.Code)
	}
	ops, _ := AppEngine{P: p}.History(history.Filter{Source: history.SourceWeb})
	if len(ops) != 1 || ops[0].Command != "host add" || ops[0].Result != history.ResultOK {
		t.Errorf("recorded %+v", ops)
	}
}

// A confirmation for a preview that no longer holds is refused with the new
// preview; so is one whose hash was tampered with.
func TestAStaleConfirmationShowsTheNewPreview(t *testing.T) {
	s, p, _ := newTestServer(t)
	t.Cleanup(mutation.Release)
	c := signIn(t, s)
	m := hashField.FindStringSubmatch(c.change("/changes/preview", addHost("db")).Body.String())
	if m == nil {
		t.Fatal("no hash")
	}
	// The manifest moves under the preview.
	f := addHost("other")
	f.Set("hash", hashField.FindStringSubmatch(c.change("/changes/preview", addHost("other")).Body.String())[1])
	if rec := c.change("/changes/apply", f); rec.Code != http.StatusOK {
		t.Fatalf("setup apply: %d", rec.Code)
	}
	before, _ := os.ReadFile(p.Manifest())
	f = addHost("db")
	f.Set("hash", m[1])
	rec := c.change("/changes/apply", f)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Something changed since you looked") {
		t.Fatalf("stale apply: %d\n%s", rec.Code, rec.Body.String())
	}
	if !hashField.MatchString(rec.Body.String()) {
		t.Error("the refusal does not offer the new preview to confirm")
	}
	f.Set("hash", strings.Repeat("0", 64))
	if rec := c.change("/changes/apply", f); rec.Code != http.StatusConflict {
		t.Errorf("tampered hash: %d", rec.Code)
	}
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(before) {
		t.Error("a refused confirmation wrote the manifest")
	}
}

func TestChangesNeedTheFormTokenAndValidNames(t *testing.T) {
	s, p, _ := newTestServer(t)
	c := signIn(t, s)
	if rec := c.post("/changes/preview", addHost("db").Encode()); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF token: %d, want 403", rec.Code)
	}
	for _, bad := range []url.Values{
		{"action": {"host-add"}, "profile": {"work"}, "alias": {"../etc"}, "hostname": {"x"}, "user": {"u"}},
		{"action": {"host-add"}, "profile": {"../work"}, "alias": {"x"}, "hostname": {"x"}, "user": {"u"}},
		{"action": {"host-add"}, "profile": {"work"}, "alias": {"x"}, "hostname": {"x\nProxyCommand evil"}, "user": {"u"}},
		{"action": {"host-add"}, "profile": {"work"}, "alias": {"x"}, "hostname": {"x"}, "user": {"u"}, "port": {"99999"}},
		{"action": {"rm-rf"}},
		{"action": {"vm-add"}, "profile": {"work"}, "alias": {"x"}, "hypervisor": {"nope"}, "vm": {"v"}, "user": {"u"}},
	} {
		if rec := c.change("/changes/preview", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v: %d, want 400", bad, rec.Code)
		}
	}
	before, _ := os.ReadFile(p.Manifest())
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(before) {
		t.Error("a refused form wrote the manifest")
	}
}

// A preview that would fail says so and offers no confirm button.
func TestAFailingPreviewCannotBeConfirmed(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	f := addHost("db")
	f.Set("profile", "nope")
	body := c.change("/changes/preview", f).Body.String()
	if !strings.Contains(body, "would fail") || hashField.MatchString(body) {
		t.Errorf("a failing preview should explain and offer nothing to confirm:\n%s", body)
	}
}

func TestReadOnlyServesNoChangeAndShowsNoForm(t *testing.T) {
	p, _ := fixtureHome(t)
	s, err := New(Options{Engine: AppEngine{P: p}, Token: testToken, AllowedHosts: AllowedHosts("127.0.0.1", 7822, nil), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	c := signIn(t, s)
	for _, path := range []string{"/changes/preview", "/changes/apply"} {
		if rec := c.change(path, addHost("db")); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("read-only %s: %d, want 405", path, rec.Code)
		}
	}
	for _, page := range []string{"/", "/profiles", "/hosts", "/hosts/gh", "/keys"} {
		if strings.Contains(c.get(page).Body.String(), "/changes/preview") {
			t.Errorf("read-only %s shows a change form", page)
		}
	}
}

// Every form on every page names an action the server knows, so no button
// leads to "unknown action".
func TestEveryFormNamesAKnownAction(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	action := regexp.MustCompile(`name="action" value="([a-z-]+)"`)
	seen := map[string]bool{}
	for _, page := range []string{"/", "/profiles", "/hosts", "/hosts/gh", "/keys"} {
		for _, m := range action.FindAllStringSubmatch(c.get(page).Body.String(), -1) {
			seen[m[1]] = true
			if _, ok := actionFields[m[1]]; !ok {
				t.Errorf("%s posts unknown action %q", page, m[1])
			}
		}
	}
	for _, want := range []string{"profile-add", "profile-edit", "profile-delete", "host-add", "host-edit", "host-delete", "vm-add", "config-render"} {
		if !seen[want] {
			t.Errorf("no page offers %s", want)
		}
	}
}
