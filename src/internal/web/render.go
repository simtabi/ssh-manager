package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/expiry"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
)

// assetSet is the embedded assets with a content hash each, for
// fingerprinted, immutable URLs.
type assetSet struct {
	files  map[string][]byte // path below assets/
	hashes map[string]string // first 12 hex chars of sha256
	sprite template.HTML
}

func loadAssets() (*assetSet, error) {
	a := &assetSet{files: map[string][]byte{}, hashes: map[string]string{}}
	err := fs.WalkDir(assetFS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := assetFS.ReadFile(p)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(p, "assets/")
		sum := sha256.Sum256(body)
		a.files[name] = body
		a.hashes[name] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
	if err != nil {
		return nil, err
	}
	sprite, ok := a.files["vendor/tabler-icons.svg"]
	if !ok {
		return nil, fmt.Errorf("web: the icon sprite is not embedded")
	}
	// The sprite is vendored, hash-checked by a test, and contains no script:
	// it is inlined so <use href="#..."> stays same-document.
	a.sprite = template.HTML(sprite) //nolint:gosec // trusted vendored file, see above
	return a, nil
}

// url returns the fingerprinted URL of an asset. Asking for one that does not
// exist fails the template, which the page tests turn into a failure rather
// than a broken page.
func (a *assetSet) url(name string) (string, error) {
	h, ok := a.hashes[name]
	if !ok {
		return "", fmt.Errorf("no embedded asset %q", name)
	}
	return "/assets/" + h + "/" + name, nil
}

// pageSet is every page template, each parsed once over the shared layout.
type pageSet struct {
	pages map[string]*template.Template
}

func pageNames() ([]string, error) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == "layout.html" || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".html"))
	}
	sort.Strings(out)
	return out, nil
}

func funcs(a *assetSet) template.FuncMap {
	return template.FuncMap{
		"asset":  a.url,
		"sprite": func() template.HTML { return a.sprite },
		"icon":   iconHTML,
		"when":   func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"stamp": func(s string) string {
			if t, err := time.Parse(history.TimeFormat, s); err == nil {
				return t.UTC().Format("2006-01-02 15:04:05 UTC")
			}
			return s
		},
		"orDash": func(s string) string {
			if s == "" {
				return "–"
			}
			return s
		},
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"join":  strings.Join,
		"list":  func(xs ...string) []string { return xs },
		"short": func(s string) string { return shorten(s, 8) },
		"size":  humanSize,
		"resultClass": func(r string) string {
			switch r {
			case history.ResultOK:
				return "badge-ok"
			case history.ResultDryRun:
				return "badge-info"
			case history.ResultAborted:
				return "badge-muted"
			case "":
				return "badge-warn"
			}
			return "badge-bad"
		},
		"statusClass": func(s string) string {
			switch s {
			case "deployed", "ok":
				return "badge-ok"
			case "needs-redeploy", "due_soon":
				return "badge-warn"
			case "no-key", "overdue":
				return "badge-bad"
			}
			return "badge-muted"
		},
		"expiryDays": func(s expiry.Status) string {
			if s.DaysRemaining == nil {
				return "–"
			}
			if *s.DaysRemaining < 0 {
				return fmt.Sprintf("%d days ago", -*s.DaysRemaining)
			}
			return fmt.Sprintf("in %d days", *s.DaysRemaining)
		},
		"diffClass": func(op byte) string {
			switch op {
			case '+':
				return "diff-add"
			case '-':
				return "diff-del"
			case '@':
				return "diff-hunk"
			}
			return "diff-ctx"
		},
		"diffMark": func(op byte) string {
			if op == '@' {
				return "⋯"
			}
			return string(op)
		},
		"subjects": func(subs []history.Subject) string {
			var parts []string
			for _, s := range subs {
				parts = append(parts, s.Kind+" "+s.Name)
			}
			return strings.Join(parts, ", ")
		},
		"navItem": func(v view, key, href, icon, label string) navItem {
			return navItem{Active: v.Nav == key, Href: href, Icon: icon, Label: label}
		},
	}
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// iconHTML renders a Tabler icon from the inline sprite. Icons are
// decorative here: every one sits beside text that says the same thing.
func iconHTML(name string) template.HTML {
	if !validIcon(name) {
		return ""
	}
	return template.HTML(`<svg class="icon" aria-hidden="true" focusable="false"><use href="#tabler-` + name + `"></use></svg>`) //nolint:gosec // name is [a-z0-9-] only
}

func validIcon(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func parsePages(a *assetSet) (*pageSet, error) {
	base, err := template.New("layout.html").Funcs(funcs(a)).ParseFS(templateFS, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	names, err := pageNames()
	if err != nil {
		return nil, err
	}
	ps := &pageSet{pages: map[string]*template.Template{}}
	for _, n := range names {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templateFS, path.Join("templates", n+".html")); err != nil {
			return nil, err
		}
		ps.pages[n] = t
	}
	return ps, nil
}

type navItem struct {
	Active            bool
	Href, Icon, Label string
}

// view is what every page template receives.
type view struct {
	Title    string
	Nav      string
	Authed   bool
	CSRF     string
	Version  string
	ReadOnly bool
	Home     string
	SSHDir   string
	DevRoot  string
	Data     any
}

func (s *Server) newView(r *http.Request, nav, title string, data any) view {
	p := s.opts.Engine.Home()
	v := view{Title: title, Nav: nav, Version: s.opts.Version, ReadOnly: s.opts.ReadOnly, Data: data,
		Home: p.ConfigDir, SSHDir: p.SSHDir, DevRoot: p.DevRoot}
	if sess := sessionFrom(r.Context()); sess != nil {
		v.Authed = true
		v.CSRF = sess.csrf
	}
	return v
}

// render executes a page into a buffer first, so a template error becomes a
// clean 500 instead of half a page.
func (s *Server) render(w http.ResponseWriter, status int, page string, v view) {
	t, ok := s.pages.pages[page]
	if !ok {
		http.Error(w, "no such page template: "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", v); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type errorData struct {
	Status         int
	Heading        string
	Message        string
	Link, LinkText string
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	s.render(w, status, "error", s.newView(r, "", heading, errorData{Status: status, Heading: heading, Message: message}))
}

func (s *Server) renderUnauthorized(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusUnauthorized, "Sign-in link required",
		"Open the address `sshmgr serve` printed when it started. It carries a one-time token that signs this browser in.")
}

// serveAsset answers /assets/{hash}/{path...}. A stale hash is a 404, not the
// current file: an immutable URL must never change content.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	body, ok := s.assets.files[name]
	if !ok || r.PathValue("hash") != s.assets.hashes[name] {
		http.NotFound(w, r)
		return
	}
	switch path.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(body)
}
