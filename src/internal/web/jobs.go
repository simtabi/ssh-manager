package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/bundler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/deployer"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/jobs"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/rotator"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// A job is a change that reaches other machines - deploy, rotate, rollback -
// so no copy can preview it. POST /jobs/review says what it will do and what
// it is the same as; POST /jobs starts it, and its page streams the output
// from GET /jobs/{id}/events. One job runs at a time, under the lock for as
// long as it runs. A job can ask a question (rotate's "pasted the key?"),
// answered at POST /jobs/{id}/answer, and be cancelled between its steps at
// POST /jobs/{id}/cancel. Nothing a job runs can prompt: ssh and ssh-copy-id
// run with stdin closed and BatchMode=yes (W12), and passphrases are never
// taken.

// jobFields are the form fields each job reads.
var jobFields = map[string][]string{
	"deploy":   {"key", "target"},
	"rotate":   {"key", "allow_unverified"},
	"rollback": {"key"},
}

// jobSpec is a job ready to start: what it is, what it will do, and the steps.
type jobSpec struct {
	scope mutation.Scope
	what  []string
	run   func(j *jobs.Job) error
}

// keyRef reads a "profile/key" field.
func keyRef(f url.Values) (manifest.KeyRef, error) {
	profile, key, ok := strings.Cut(strings.TrimSpace(f.Get("key")), "/")
	if !ok || !nameRe.MatchString(profile) || !nameRe.MatchString(key) {
		return manifest.KeyRef{}, badForm("key must be profile/key, each a name sshmgr accepts")
	}
	return manifest.KeyRef{Profile: profile, KeyName: key}, nil
}

// buildJob turns a form into the job it asks for.
func buildJob(f url.Values, h home) (jobSpec, error) {
	action := f.Get("action")
	if _, ok := jobFields[action]; !ok {
		return jobSpec{}, badForm("unknown job %q", action)
	}
	ref, err := keyRef(f)
	if err != nil {
		return jobSpec{}, err
	}
	key := ref.String()
	subjects := []history.Subject{{Kind: history.KindProfile, Name: ref.Profile}, {Kind: history.KindKey, Name: ref.KeyName}}
	retain := h.retain
	if retain < 1 {
		retain = 10
	}
	switch action {
	case "deploy":
		target, err := optionalName(f, "target")
		if err != nil {
			return jobSpec{}, err
		}
		args := []string{key}
		where := "every host that uses it"
		if target != "" {
			args, where = append(args, target), target
		}
		return jobSpec{
			scope: mutation.Scope{Command: "deploy", Args: append(args, "--yes"), Source: history.SourceWeb, Subjects: subjects},
			what: []string{
				"installs the public half of " + key + " on " + where + ", and records where it went",
				"snapshots ~/.ssh first",
				"cannot answer a password prompt: a target that needs a password fails, and is deployed from a terminal",
			},
			run: func(j *jobs.Job) error { return deployJob(j, h.p, retain, key, target) },
		}, nil
	case "rotate":
		allow := checked(f, "allow_unverified")
		args := []string{key, "--yes"}
		if allow {
			args = append(args, "--allow-unverified")
		}
		return jobSpec{
			scope: mutation.Scope{Command: "rotate", Args: args, Source: history.SourceWeb, Subjects: subjects},
			what: []string{
				"writes an encrypted backup of ~/.ssh and the config first, so it needs SSH_MANAGER_AGE_RECIPIENT",
				"mints a new " + key + ", deploys it to every host that uses the key, and proves each login",
				"moves the current key to old/, replacing any earlier predecessor, once every target is done",
				"asks you to paste the new public key where a target takes it by hand, and waits",
			},
			run: func(j *jobs.Job) error { return rotateJob(j, h.p, retain, key, allow) },
		}, nil
	default: // rollback
		return jobSpec{
			scope: mutation.Scope{Command: "rollback", Args: []string{key, "--yes"}, Source: history.SourceWeb, Subjects: subjects},
			what: []string{
				"puts " + key + "'s old/ predecessor back, and keeps the rotated-in key in old/ so this can be undone",
				"checks every target is reachable first, and changes nothing if one is not",
				"deploys the restored key to each target, and snapshots ~/.ssh first",
			},
			run: func(j *jobs.Job) error { return rollbackJob(j, h.p, retain, key) },
		}, nil
	}
}

func loadState(p paths.Paths) (*manifest.Manifest, *inventory.Inventory, error) {
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		return nil, nil, err
	}
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		return nil, nil, err
	}
	return m, inv, nil
}

// deployJob is `sshmgr deploy` after its confirmation.
func deployJob(j *jobs.Job, p paths.Paths, retain int, key, target string) error {
	m, inv, err := loadState(p)
	if err != nil {
		return err
	}
	mutation.SnapshotBeforeMutation(p, retain)
	if err := j.Step(); err != nil {
		return err
	}
	report, err := deployer.New(p, m, inv).Unattended(j).Deploy(key, target)
	if err != nil {
		return err
	}
	if err := inv.Save(p.Inventory()); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(j, report.Format())
	if report.AnyError() {
		return errors.New("not every target took the key; see above")
	}
	return nil
}

// rotateJob is rotate's single-key path after its confirmation. A target that
// takes the key by hand pauses the job with the new public key to paste.
func rotateJob(j *jobs.Job, p paths.Paths, retain int, key string, allowUnverified bool) error {
	if err := bundler.BackupBeforeDestroying(p, j, false); err != nil {
		return err
	}
	m, inv, err := loadState(p)
	if err != nil {
		return err
	}
	mutation.SnapshotBeforeMutation(p, retain)
	if err := j.Step(); err != nil {
		return err
	}
	r := rotator.New(p, m, inv).Unattended(j).WithManualStep(func(alias, where, pubkey string) bool {
		_, _ = fmt.Fprintf(j, "%s: this target takes the key by hand. %s\n", alias, where)
		return j.Ask("Paste this key where "+alias+" takes it, then confirm: sshmgr will log in with it to prove it.",
			strings.TrimSpace(pubkey))
	})
	report, err := r.Rotate(key, allowUnverified, "")
	if err != nil {
		return err
	}
	if report.Committed {
		if err := inv.Save(p.Inventory()); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintln(j, report.Format())
	if !report.Committed {
		return errors.New("the rotation did not complete; see above")
	}
	return nil
}

// rollbackJob is `sshmgr rollback` after its confirmation.
func rollbackJob(j *jobs.Job, p paths.Paths, retain int, key string) error {
	m, inv, err := loadState(p)
	if err != nil {
		return err
	}
	mutation.SnapshotBeforeMutation(p, retain)
	if err := j.Step(); err != nil {
		return err
	}
	report, err := rotator.New(p, m, inv).Unattended(j).Rollback(key)
	if err != nil {
		return err
	}
	if err := inv.Save(p.Inventory()); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(j, report.Format())
	if !report.Committed {
		return errors.New("the rollback did not complete; see above")
	}
	return nil
}

type jobReview struct {
	Command string
	What    []string
	Fields  []formField
	Busy    *jobs.View
}

func jobCommand(s mutation.Scope) string {
	return strings.TrimSpace("sshmgr " + s.Command + " " + strings.Join(s.Args, " "))
}

func carriedJob(f url.Values) []formField {
	out := []formField{{"action", f.Get("action")}}
	for _, k := range jobFields[f.Get("action")] {
		if f.Has(k) {
			out = append(out, formField{k, f.Get(k)})
		}
	}
	return out
}

// jobPages holds the job handlers, kept off pages for the same reason pages
// is kept off Server: no type grows into a facade.
type jobPages struct{ s *Server }

func (h jobPages) fail(w http.ResponseWriter, r *http.Request, err error) { pages(h).fail(w, r, err) }

func (h jobPages) parseJob(w http.ResponseWriter, r *http.Request) (jobSpec, bool) {
	if err := r.ParseForm(); err != nil {
		h.s.renderError(w, r, http.StatusBadRequest, "Unreadable form", err.Error())
		return jobSpec{}, false
	}
	spec, err := buildJob(r.PostForm, home{p: h.s.opts.Engine.Home(), retain: h.s.opts.Retain})
	if err != nil {
		h.s.renderError(w, r, http.StatusBadRequest, "That job cannot be run", err.Error())
		return jobSpec{}, false
	}
	return spec, true
}

func (h jobPages) handleJobReview(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.parseJob(w, r)
	if !ok {
		return
	}
	rev := jobReview{Command: jobCommand(spec.scope), What: spec.what, Fields: carriedJob(r.PostForm)}
	if j := h.s.jobs.Running(); j != nil {
		v, _ := j.View()
		rev.Busy = &v
	}
	h.s.render(w, http.StatusOK, "job_review", h.s.newView(r, "", "Review the job", rev))
}

func (h jobPages) handleJobStart(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.parseJob(w, r)
	if !ok {
		return
	}
	j, err := h.s.jobs.Start(h.s.opts.Engine.Home(), spec.scope, spec.run)
	var busy jobs.ErrBusy
	switch {
	case errors.As(err, &busy):
		http.Redirect(w, r, "/jobs/"+busy.ID, http.StatusSeeOther)
	case err != nil:
		h.s.renderError(w, r, http.StatusConflict, "The job was not started", err.Error())
	default:
		v, _ := j.View()
		http.Redirect(w, r, "/jobs/"+v.ID, http.StatusSeeOther)
	}
}

func (h jobPages) job(w http.ResponseWriter, r *http.Request) *jobs.Job {
	id := r.PathValue("id")
	j := h.s.jobs.Get(id)
	if j == nil || !nameRe.MatchString(id) {
		h.fail(w, r, ErrNotFound)
		return nil
	}
	return j
}

func (h jobPages) handleJob(w http.ResponseWriter, r *http.Request) {
	j := h.job(w, r)
	if j == nil {
		return
	}
	v, _ := j.View()
	h.s.render(w, http.StatusOK, "job", h.s.newView(r, "", "sshmgr "+v.Command, v))
}

// handleJobEvents streams a job's output as server-sent events: each new
// line as a "line" event, and the job's state as a "state" event whenever it
// changes. The stream ends with the job.
func (h jobPages) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	j := h.job(w, r)
	if j == nil {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	sent, state := 0, ""
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		v, changed := j.View()
		for ; sent < len(v.Lines); sent++ {
			writeEvent(w, "line", v.Lines[sent])
		}
		if v.State != state {
			state = v.State
			writeEvent(w, "state", state)
		}
		flusher.Flush()
		if state == jobs.Done || state == jobs.Failed || state == jobs.Cancelled {
			return
		}
		select {
		case <-changed:
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": still running\n\n")
		case <-r.Context().Done():
			return
		}
	}
}

// writeEvent writes one event. A line holds no newline, so it is one data field.
func writeEvent(w io.Writer, event, data string) {
	data = strings.NewReplacer("\r", "", "\n", " ").Replace(data)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}

func (h jobPages) handleJobAnswer(w http.ResponseWriter, r *http.Request) {
	j := h.job(w, r)
	if j == nil {
		return
	}
	v, _ := j.View()
	if !h.s.jobs.Answer(v.ID, r.PostFormValue("answer") == "yes") {
		h.s.renderError(w, r, http.StatusConflict, "Nothing to answer", "The job is not waiting on a question.")
		return
	}
	http.Redirect(w, r, "/jobs/"+v.ID, http.StatusSeeOther)
}

func (h jobPages) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	j := h.job(w, r)
	if j == nil {
		return
	}
	v, _ := j.View()
	h.s.jobs.Cancel(v.ID)
	http.Redirect(w, r, "/jobs/"+v.ID, http.StatusSeeOther)
}
