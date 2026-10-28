package web

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/build"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/tabler"
)

// Every page renders against a real home, through the real engine, and says
// what it is about. A template error would be a 500 with "template error".
func TestEveryPageRenders(t *testing.T) {
	s, _, opID := newTestServer(t)
	c := signIn(t, s)
	pages := map[string]string{
		"/":                                     "Needs attention",
		"/profiles":                             "work",
		"/hosts":                                "github.com",
		"/hosts/gh":                             "Rendered block",
		"/keys":                                 "work/",
		"/snapshots":                            "ssh-20261001-100000.tar.gz",
		"/snapshots/ssh-20261001-100000.tar.gz": "old.github.com",
		"/history":                              "host add",
		"/history/" + opID:                      "host.add",
		"/history/" + opID[:8]:                  "Manifest",
		"/doctor":                               "sshmgr doctor",
		"/audit":                                "Deployments",
		"/about/licenses":                       "Permission is hereby granted",
	}
	if len(pages) < 13 {
		t.Fatal("the page list shrank")
	}
	for path, want := range pages {
		rec := c.get(path)
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d\n%s", path, rec.Code, body)
			continue
		}
		if !strings.Contains(body, want) {
			t.Errorf("%s does not mention %q", path, want)
		}
		if strings.Contains(body, "template error") {
			t.Errorf("%s: %s", path, body)
		}
	}
	// The key page, found from the list rather than guessed.
	keys := c.get("/keys").Body.String()
	m := regexp.MustCompile(`href="(/keys/work/[^"]+)"`).FindStringSubmatch(keys)
	if m == nil {
		t.Fatalf("the key list links no key:\n%s", keys)
	}
	if rec := c.get(m[1]); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Identity file") {
		t.Errorf("%s: %d", m[1], rec.Code)
	}
}

// The operation page shows the manifest diff the history recorded.
func TestTheOperationPageShowsTheManifestDiff(t *testing.T) {
	s, _, opID := newTestServer(t)
	body := signIn(t, s).get("/history/" + opID).Body.String()
	for _, want := range []string{`diff-del`, `&#34;a&#34;: 1`, `diff-add`, `&#34;a&#34;: 2`} {
		if !strings.Contains(body, want) {
			t.Errorf("the operation page is missing %s", want)
		}
	}
}

// Names that resolve to nothing are 404s, and nothing is ever joined onto a
// path: a traversal attempt is just another unknown name.
func TestUnknownNamesAreNotFound(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	for _, path := range []string{
		"/hosts/nope", "/keys/work/nope", "/keys/nope/x", "/snapshots/nope.tar.gz",
		"/snapshots/..%2F..%2Fcfg%2Fmanifest.json", "/snapshots/ssh-20261001-100000.tar.gz?against=..%2Fx",
		"/history/ffffffffffff", "/history/..%2F..", "/history/NOTHEX", "/nope",
	} {
		if rec := c.get(path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, rec.Code)
		}
	}
}

// A snapshot from before private keys were excluded is listed but never
// opened, and no page anywhere shows the key that sits on disk.
func TestNoPageShowsKeyMaterial(t *testing.T) {
	s, _, opID := newTestServer(t)
	c := signIn(t, s)
	legacy := c.get("/snapshots/ssh-20260901-100000.tar.gz").Body.String()
	if !strings.Contains(legacy, "holds private keys") {
		t.Errorf("the key-bearing snapshot was not refused:\n%s", legacy)
	}
	against := c.get("/snapshots/ssh-20261001-100000.tar.gz?against=ssh-20260901-100000.tar.gz").Body.String()
	if !strings.Contains(against, "holds private keys") {
		t.Error("comparing against a key-bearing snapshot opened it")
	}
	n := 0
	for _, path := range []string{"/", "/profiles", "/hosts", "/hosts/gh", "/keys", "/snapshots",
		"/snapshots/ssh-20260901-100000.tar.gz", "/snapshots/ssh-20261001-100000.tar.gz",
		"/snapshots/ssh-20261001-100000.tar.gz?against=ssh-20260901-100000.tar.gz",
		"/history", "/history/" + opID, "/doctor", "/audit"} {
		body := c.get(path).Body.String()
		n++
		if strings.Contains(body, "OPENSSH PRIVATE KEY") || strings.Contains(body, "secret\n") {
			t.Errorf("%s shows key material", path)
		}
	}
	if n < 13 {
		t.Fatalf("scanned %d pages", n)
	}
}

// Reading must not write: a page view must not create the history database
// or run its first import, which would happen outside the lock.
func TestPagesDoNotCreateTheHistory(t *testing.T) {
	s, p, _ := newTestServer(t)
	for _, f := range []string{p.HistoryDB(), p.HistoryDB() + "-wal", p.HistoryDB() + "-shm"} {
		_ = os.Remove(f)
	}
	c := signIn(t, s)
	for _, path := range []string{"/", "/history", "/audit", "/keys"} {
		if rec := c.get(path); rec.Code != http.StatusOK {
			t.Errorf("%s without a history: %d", path, rec.Code)
		}
	}
	if _, err := os.Stat(p.HistoryDB()); err == nil {
		t.Error("a page view created the history database")
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	css, _ := s.assets.url("app.css")
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"page":       c.get("/hosts"),
		"401":        do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/", nil)),
		"bad host":   do(s, httptest.NewRequest(http.MethodGet, "http://evil.example/", nil)),
		"404":        c.get("/nope"),
		"token swap": do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/?token="+testToken, nil)),
		"asset":      c.get(css),
		"post":       c.post("/hosts", "x=1"),
	} {
		h := rec.Header()
		if h.Get("Content-Security-Policy") != ContentSecurityPolicy || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers %v", name, h)
		}
	}
}

func TestAuth(t *testing.T) {
	s, _, _ := newTestServer(t)
	if rec := do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/hosts", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", rec.Code)
	}
	if rec := do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/?token=wrong", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	rec := do(s, httptest.NewRequest(http.MethodGet, "http://"+testHost+"/hosts?token="+testToken+"&theme=dark", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("token: %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "token") || !strings.Contains(loc, "/hosts") {
		t.Errorf("the redirect keeps the token or loses the page: %s", loc)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie %+v", cookie)
	}
	r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/hosts", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "forged"})
	if rec := do(s, r); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", rec.Code)
	}
}

func TestHostCheckRefusesARebindingHost(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	for _, host := range []string{"evil.example", "evil.example:7822", "127.0.0.1:9999", "localhost.evil.example:7822"} {
		r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/hosts", nil)
		r.Host = host
		r.AddCookie(c.cookie)
		if rec := do(s, r); rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %s: %d, want 421", host, rec.Code)
		}
	}
	for _, host := range []string{"127.0.0.1:7822", "localhost:7822", "[::1]:7822"} {
		r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/hosts", nil)
		r.Host = host
		r.AddCookie(c.cookie)
		if rec := do(s, r); rec.Code != http.StatusOK {
			t.Errorf("Host %s: %d, want 200", host, rec.Code)
		}
	}
}

// Nothing changes state in this phase: a POST without the session's CSRF
// token is refused, and one with it finds no route that would act.
func TestNoRouteChangesAnything(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	if rec := c.post("/hosts", "x=1"); rec.Code != http.StatusForbidden {
		t.Errorf("POST without a CSRF token: %d, want 403", rec.Code)
	}
	sess := s.sessions.get(c.cookie.Value)
	for _, path := range []string{"/", "/hosts", "/hosts/gh", "/snapshots/ssh-20261001-100000.tar.gz"} {
		if rec := c.post(path, csrfField+"="+sess.csrf); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s with a valid token: %d, want 405", path, rec.Code)
		}
	}
}

func TestStaleAssetHashIsNotFound(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := signIn(t, s)
	u, _ := s.assets.url("app.css")
	if rec := c.get(u); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset: %d %v", rec.Code, rec.Header())
	}
	if rec := c.get("/assets/000000000000/app.css"); rec.Code != http.StatusNotFound {
		t.Errorf("stale hash: %d", rec.Code)
	}
}

const module = "github.com/simtabi/ssh-manager/src/v3"

// The web layer must never reach internal/cli: it holds the TUI and the
// process-wide state of one command run, which a long-lived server serving
// several browsers cannot share.
func TestWebDoesNotImportTheCommandLine(t *testing.T) {
	seen := map[string]bool{}
	var walk func(path, dir string)
	walk = func(path, dir string) {
		if seen[path] {
			return
		}
		seen[path] = true
		pkg, err := build.Import(path, dir, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, imp := range pkg.Imports {
			if strings.HasPrefix(imp, module+"/") {
				walk(imp, pkg.Dir)
			}
		}
	}
	walk(module+"/internal/web", ".")
	if len(seen) < 10 {
		t.Fatalf("walked %d packages; the import walk is not finding the module", len(seen))
	}
	if seen[module+"/internal/cli"] {
		t.Error("internal/web depends on internal/cli")
	}
	if !seen[module+"/internal/services/overview"] {
		t.Error("the walk did not reach services/overview, so it proves nothing")
	}
}

func vendorFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := assetFS.ReadFile("assets/vendor/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every vendored file hashes to what MANIFEST.sha256 recorded when the
// vendoring tool wrote it, so a hand edit or a partial update fails here.
func TestVendoredFilesMatchTheManifest(t *testing.T) {
	sc := bufio.NewScanner(bytes.NewReader(vendorFile(t, "MANIFEST.sha256")))
	n := 0
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("bad manifest line %q", sc.Text())
		}
		got := sha256.Sum256(vendorFile(t, name))
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s does not match MANIFEST.sha256; re-run make tabler-vendor", name)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("manifest lists %d files, want at least 10", n)
	}
}

// THIRD_PARTY_NOTICES.md is exactly what the vendoring tool generates from the
// embedded licences, so the release archives ship what the binary serves.
func TestNoticesMatchTheEmbeddedLicences(t *testing.T) {
	vers, err := tabler.ParseVersions(vendorFile(t, tabler.VersionFile))
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string][]byte{}
	for _, f := range []string{"tabler.txt", "tabler-icons.txt", "bootstrap.txt", "popper.txt"} {
		texts[f] = vendorFile(t, "LICENSES/"+f)
	}
	ls := tabler.Licences(vers, texts)
	if len(ls) != 4 {
		t.Fatalf("%d licences", len(ls))
	}
	root, err := os.ReadFile(filepath.Join("..", "..", "..", "THIRD_PARTY_NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, tabler.Notices(ls)) {
		t.Error("THIRD_PARTY_NOTICES.md is out of date; re-run make tabler-vendor")
	}
}

var iconCall = regexp.MustCompile(`(?:icon|navItem \. "[^"]+" "[^"]+") "([a-z0-9-]+)"`)

// Every icon a template asks for is in the sprite: a missing one renders as
// nothing at all.
func TestEveryIconUsedIsInTheSprite(t *testing.T) {
	sprite := string(vendorFile(t, "tabler-icons.svg"))
	for _, n := range tabler.ReadIconList(vendorFile(t, "icons.txt")) {
		if !strings.Contains(sprite, `id="tabler-`+n+`"`) {
			t.Errorf("icons.txt lists %s but the sprite lacks it", n)
		}
	}
	used := 0
	var files []string
	entries, _ := templateFS.ReadDir("templates")
	for _, e := range entries {
		if e.IsDir() {
			sub, _ := templateFS.ReadDir("templates/" + e.Name())
			for _, f := range sub {
				files = append(files, "templates/"+e.Name()+"/"+f.Name())
			}
			continue
		}
		files = append(files, "templates/"+e.Name())
	}
	for _, f := range files {
		body, _ := templateFS.ReadFile(f)
		for _, m := range iconCall.FindAllStringSubmatch(string(body), -1) {
			used++
			if !strings.Contains(sprite, `id="tabler-`+m[1]+`"`) {
				t.Errorf("%s uses icon %s, which is not in the sprite; add it to icons.txt", f, m[1])
			}
		}
	}
	if used < 10 {
		t.Fatalf("found %d icon uses, want at least 10", used)
	}
}
