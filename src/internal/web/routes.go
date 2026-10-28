package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
)

// routes registers every page. Each takes names from the path, the query or
// the form, never a filesystem path, and the engine resolves each name against
// what exists. Only the POST routes change anything - the changes and the jobs
// (see jobs.go) - and --read-only registers none of them, nor the job pages.
func (s *Server) routes() http.Handler {
	h, jh := pages{s}, jobPages{s}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/{hash}/{path...}", s.serveAsset)
	mux.HandleFunc("GET /{$}", h.handleOverview)
	mux.HandleFunc("GET /profiles", h.handleProfiles)
	mux.HandleFunc("GET /hosts", h.handleHosts)
	mux.HandleFunc("GET /hosts/{alias}", h.handleHost)
	mux.HandleFunc("GET /keys", h.handleKeys)
	mux.HandleFunc("GET /keys/{profile}/{key}", h.handleKey)
	mux.HandleFunc("GET /snapshots", h.handleSnapshots)
	mux.HandleFunc("GET /snapshots/{id}", h.handleSnapshot)
	mux.HandleFunc("GET /history", h.handleHistory)
	mux.HandleFunc("GET /history/{op}", h.handleOp)
	mux.HandleFunc("GET /doctor", h.handleDoctor)
	mux.HandleFunc("GET /audit", h.handleAudit)
	mux.HandleFunc("GET /exports/{name}", h.handleExport)
	mux.HandleFunc("GET /about/licenses", h.handleLicences)
	if !s.opts.ReadOnly {
		mux.HandleFunc("POST /changes/preview", h.handlePreview)
		mux.HandleFunc("POST /changes/apply", h.handleApply)
		mux.HandleFunc("POST /jobs/review", jh.handleJobReview)
		mux.HandleFunc("POST /jobs", jh.handleJobStart)
		mux.HandleFunc("GET /jobs/{id}", jh.handleJob)
		mux.HandleFunc("GET /jobs/{id}/events", jh.handleJobEvents)
		mux.HandleFunc("POST /jobs/{id}/answer", jh.handleJobAnswer)
		mux.HandleFunc("POST /jobs/{id}/cancel", jh.handleJobCancel)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.renderError(w, r, http.StatusMethodNotAllowed, "Not a change",
				"Changes are made from the forms on these pages, or with the sshmgr command.")
			return
		}
		s.renderError(w, r, http.StatusNotFound, "Not found", "There is no page at this address.")
	})
	return mux
}

// pages holds the page handlers, kept off Server so neither type grows into
// the facade cmd/sshmgr's layering test guards against.
type pages struct{ s *Server }

// fail renders an engine error: a name that matched nothing is a 404, and
// anything else is a 500 with the message, which is the CLI's own wording.
func (h pages) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		h.s.renderError(w, r, http.StatusNotFound, "Not found", "Nothing by that name is in this sshmgr home.")
		return
	}
	h.s.renderError(w, r, http.StatusInternalServerError, "Could not read the sshmgr home", err.Error())
}

func (h pages) handleOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := h.s.opts.Engine.Overview(h.s.now())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "overview", h.s.newView(r, "overview", "Overview", ov))
}

func (h pages) handleProfiles(w http.ResponseWriter, r *http.Request) {
	ps, err := h.s.opts.Engine.Profiles()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "profiles", h.s.newView(r, "profiles", "Profiles", ps))
}

func (h pages) handleHosts(w http.ResponseWriter, r *http.Request) {
	groups, err := h.s.opts.Engine.Hosts()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "hosts", h.s.newView(r, "hosts", "Hosts", groups))
}

func (h pages) handleHost(w http.ResponseWriter, r *http.Request) {
	host, err := h.s.opts.Engine.Host(r.PathValue("alias"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "host", h.s.newView(r, "hosts", host.Detail.Alias, host))
}

func (h pages) handleKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := h.s.opts.Engine.Keys()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "keys", h.s.newView(r, "keys", "Keys", rows))
}

func (h pages) handleKey(w http.ResponseWriter, r *http.Request) {
	ref, ok := splitRef(r.PathValue("profile") + "/" + r.PathValue("key"))
	if !ok {
		h.fail(w, r, ErrNotFound)
		return
	}
	k, err := h.s.opts.Engine.Key(ref)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "key", h.s.newView(r, "keys", ref, k))
}

func (h pages) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	list, err := h.s.opts.Engine.Snapshots()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "snapshots", h.s.newView(r, "snapshots", "Snapshots", list))
}

type snapshotPage struct {
	SnapshotDiff
	Others []SnapshotView
}

func (h pages) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	d, err := h.s.opts.Engine.SnapshotDiff(r.PathValue("id"), r.URL.Query().Get("against"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	others, _ := h.s.opts.Engine.Snapshots()
	h.s.render(w, http.StatusOK, "snapshot", h.s.newView(r, "snapshots", d.ID, snapshotPage{SnapshotDiff: d, Others: others}))
}

type historyPage struct {
	Filter history.Filter
	Ops    []history.Op
	More   string // the next page's query, "" on the last page
	Query  url.Values
}

const historyPageSize = 50

func (h pages) handleHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := history.Filter{
		Host: q.Get("host"), Profile: q.Get("profile"), Key: q.Get("key"),
		Since: q.Get("since"), Until: q.Get("until"), Command: q.Get("command"), Source: q.Get("source"),
	}
	limit := historyPageSize
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	f.Limit = limit + 1 // one more than shown says whether there is a next page
	ops, err := h.s.opts.Engine.History(f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	page := historyPage{Filter: f, Query: q}
	if len(ops) > limit {
		ops = ops[:limit]
		next := url.Values{}
		for k, v := range q {
			next[k] = v
		}
		next.Set("limit", strconv.Itoa(limit+historyPageSize))
		page.More = "/history?" + next.Encode()
	}
	page.Ops = ops
	h.s.render(w, http.StatusOK, "history", h.s.newView(r, "history", "History", page))
}

func (h pages) handleOp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("op")
	if id == "" || strings.Trim(id, "0123456789abcdef") != "" {
		h.fail(w, r, ErrNotFound)
		return
	}
	v, err := h.s.opts.Engine.Op(id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "op", h.s.newView(r, "history", v.Op.Command, v))
}

func (h pages) handleDoctor(w http.ResponseWriter, r *http.Request) {
	rep, err := h.s.opts.Engine.Doctor()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "doctor", h.s.newView(r, "doctor", "Doctor", struct {
		OK     bool
		Report string
	}{rep.OK(), rep.Format()}))
}

func (h pages) handleAudit(w http.ResponseWriter, r *http.Request) {
	a, err := h.s.opts.Engine.Audit(h.s.now())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.s.render(w, http.StatusOK, "audit", h.s.newView(r, "audit", "Audit", a))
}

// handleExport downloads an export. It writes nothing, so --read-only keeps
// it: it is a page in another format.
func (h pages) handleExport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name != ExportFlat && name != ExportTermius {
		h.fail(w, r, ErrNotFound)
		return
	}
	body, err := h.s.opts.Engine.Export(name, r.URL.Query().Get("include_git") == "1")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ctype := "text/plain; charset=utf-8"
	if name == ExportTermius {
		ctype = "text/csv; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

type licence struct {
	Name, Text string
}

func (h pages) handleLicences(w http.ResponseWriter, r *http.Request) {
	var ls []licence
	for _, name := range []string{"tabler", "tabler-icons", "bootstrap", "popper"} {
		if body, ok := h.s.assets.files["vendor/LICENSES/"+name+".txt"]; ok {
			ls = append(ls, licence{Name: name, Text: string(body)})
		}
	}
	h.s.render(w, http.StatusOK, "licenses", h.s.newView(r, "", "Third-party licences", ls))
}
