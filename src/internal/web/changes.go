package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// A change is two requests. POST /changes/preview runs it against a private
// copy of the home and shows exactly what it would write, with a confirm
// button bound to the preview's hash. POST /changes/apply makes it only if a
// fresh preview, taken under the lock, still has that hash. The lock is never
// held while a person reads.
//
// Both take the same form: an action and its fields, every one a name or a
// plain value, never a path. The form is carried from the preview into the
// confirmation unchanged, so what is applied is what was previewed.

// actionFields are the form fields each action reads, in the order the
// confirmation carries them.
var actionFields = map[string][]string{
	"profile-add":       {"name", "key_scope", "key_name", "key_comment"},
	"profile-edit":      {"name", "key_scope", "key_name"},
	"profile-delete":    {"name", "purge"},
	"profile-category":  {"name", "category"},
	"host-add":          {"profile", "alias", "hostname", "user", "port", "tags"},
	"host-edit":         {"profile", "alias", "hostname", "user", "port", "tags"},
	"host-delete":       {"profile", "alias"},
	"key-delete":        {"profile", "key"},
	"vm-add":            {"profile", "alias", "hypervisor", "vm", "user"},
	"config-render":     {},
	"reconcile":         {},
	"keygen":            {"target"},
	"key-add":           {"profile", "key", "key_type", "host"},
	"providers-export":  {},
	"snapshots-prune":   {"keep"},
	"doctor-fix":        {},
	"host-apply":        {"profile", "specs", "create", "category"},
	"clean":             {"adopt"},
	"bundle":            {"keep"},
	"vm-docker-context": {"alias"},
	"snapshots-restore": {"id"},
	"notify-test":       {},
	"audit-notify":      {},
}

// nameRe is what a profile, alias or key name may be on the web: the
// characters the CLI's own names use, and nothing that could be a path.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type formError struct{ msg string }

func (e formError) Error() string { return e.msg }

func badForm(format string, a ...any) error { return formError{fmt.Sprintf(format, a...)} }

func name(f url.Values, field string) (string, error) {
	v := strings.TrimSpace(f.Get(field))
	if !nameRe.MatchString(v) {
		return "", badForm("%s %q is not a name sshmgr accepts: letters, digits, '.', '_' and '-'", field, v)
	}
	return v, nil
}

// plain is a free-text value: a hostname, a user, a comment template. It may
// not hold a control character, which nothing legitimate in those needs.
func plain(f url.Values, field string) (string, error) {
	v := strings.TrimSpace(f.Get(field))
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", badForm("%s holds a control character", field)
	}
	if len(v) > 512 {
		return "", badForm("%s is too long", field)
	}
	return v, nil
}

// optional is plain, as a pointer that is nil when the field was left empty
// on an edit form: an empty edit field means "leave it", as an unset flag does.
func optional(f url.Values, field string) (*string, error) {
	v, err := plain(f, field)
	if err != nil || v == "" {
		return nil, err
	}
	return &v, nil
}

// lines is a multi-line value - host specs - which may hold line breaks and
// tabs, and no other control character.
func lines(f url.Values, field string) (string, error) {
	v := f.Get(field)
	if strings.ContainsFunc(v, func(r rune) bool { return (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f }) {
		return "", badForm("%s holds a control character", field)
	}
	if len(v) > 16384 {
		return "", badForm("%s is too long", field)
	}
	return v, nil
}

// checked is a checkbox: "1" when ticked, absent when not.
func checked(f url.Values, field string) bool { return f.Get(field) == "1" }

// optionalName is a name field that may be left empty.
func optionalName(f url.Values, field string) (string, error) {
	if strings.TrimSpace(f.Get(field)) == "" {
		return "", nil
	}
	return name(f, field)
}

// hostSpecs parses the host apply box, one spec per line, and holds every
// alias to the same rule as a name and every hostname and user to plain.
func hostSpecs(f url.Values) ([]editor.HostSpec, error) {
	text, err := lines(f, "specs")
	if err != nil {
		return nil, err
	}
	specs, err := editor.ParseHostSpecs(strings.NewReader(text))
	if err != nil {
		return nil, badForm("%s", err.Error())
	}
	if len(specs) == 0 {
		return nil, badForm("no host specs: one per line, `<alias> <host>[:port] <user> [role]`")
	}
	for _, s := range specs {
		if !nameRe.MatchString(s.Alias) {
			return nil, badForm("alias %q is not a name sshmgr accepts: letters, digits, '.', '_' and '-'", s.Alias)
		}
		for _, v := range append([]string{s.Hostname, s.User, s.Role}, s.Tags...) {
			if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return nil, badForm("spec for %s holds a control character", s.Alias)
			}
		}
	}
	return specs, nil
}

func tagsOf(f url.Values) (*[]string, error) {
	if !f.Has("tags") {
		return nil, nil
	}
	v, err := plain(f, "tags")
	if err != nil {
		return nil, err
	}
	tags := []string{}
	for _, t := range strings.Split(v, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return &tags, nil
}

func portOf(f url.Values) (*int, error) {
	v := strings.TrimSpace(f.Get("port"))
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return nil, badForm("port %q is not 1-65535", v)
	}
	return &n, nil
}

// home is what a change needs to know about the home beyond the form: the
// snapshot restore reads its snapshot from the real home's snapshots.
type home struct {
	p      paths.Paths
	retain int
}

// buildChange turns a form into the change it asks for.
func buildChange(f url.Values, h home) (change.Change, error) {
	action := f.Get("action")
	if _, ok := actionFields[action]; !ok {
		return change.Change{}, badForm("unknown action %q", action)
	}
	var errs []error
	n := func(field string) string {
		v, err := name(f, field)
		errs = append(errs, err)
		return v
	}
	pl := func(field string) string {
		v, err := plain(f, field)
		errs = append(errs, err)
		return v
	}
	opt := func(field string) *string {
		v, err := optional(f, field)
		errs = append(errs, err)
		return v
	}
	host := func(edit bool) change.HostInput {
		in := change.HostInput{}
		if edit {
			in.Hostname, in.User = opt("hostname"), opt("user")
		} else {
			h, u := pl("hostname"), pl("user")
			if h == "" || u == "" {
				errs = append(errs, badForm("a new host needs a hostname and a user"))
			}
			in.Hostname, in.User = &h, &u
		}
		var err error
		in.Port, err = portOf(f)
		errs = append(errs, err)
		// The edit form shows the host's current tags, so what it posts is the
		// whole new list: an emptied box clears them.
		in.Tags, err = tagsOf(f)
		errs = append(errs, err)
		return in
	}
	var ch change.Change
	switch action {
	case "profile-add":
		scope := pl("key_scope")
		if scope != "" && scope != "per_service" && scope != "shared" {
			errs = append(errs, badForm("key scope must be per_service or shared"))
		}
		keyName := ""
		if strings.TrimSpace(f.Get("key_name")) != "" {
			keyName = n("key_name")
		}
		ch = change.ProfileAdd(n("name"), scope, keyName, pl("key_comment"))
	case "profile-edit":
		scope := opt("key_scope")
		if scope != nil && *scope != "per_service" && *scope != "shared" {
			errs = append(errs, badForm("key scope must be per_service or shared"))
		}
		var keyName *string
		if strings.TrimSpace(f.Get("key_name")) != "" {
			v := n("key_name")
			keyName = &v
		}
		ch = change.ProfileEdit(n("name"), scope, keyName)
	case "profile-delete":
		if checked(f, "purge") {
			ch = change.ProfilePurge(n("name"))
		} else {
			ch = change.ProfileDelete(n("name"))
		}
	case "profile-category":
		category, err := optionalName(f, "category")
		errs = append(errs, err)
		ch = change.ProfileCategory(n("name"), category)
	case "host-add":
		ch = change.HostAdd(n("profile"), n("alias"), host(false))
	case "host-edit":
		ch = change.HostEdit(n("profile"), n("alias"), host(true))
	case "host-delete":
		ch = change.HostDelete(n("profile"), n("alias"))
	case "key-delete":
		ch = change.KeyDelete(manifest.KeyRef{Profile: n("profile"), KeyName: n("key")})
	case "vm-add":
		hv := pl("hypervisor")
		known := false
		for _, h := range manifest.Hypervisors {
			known = known || h == hv
		}
		if !known {
			errs = append(errs, badForm("hypervisor must be one of %s", strings.Join(manifest.Hypervisors, ", ")))
		}
		vm, user := pl("vm"), pl("user")
		if vm == "" || user == "" {
			errs = append(errs, badForm("a VM host needs the VM's name and a guest user"))
		}
		ch = change.VMAdd(n("profile"), n("alias"), hv, vm, user)
	case "config-render":
		ch = change.ConfigRender()
	case "reconcile":
		ch = change.Reconcile()
	case "keygen":
		ch = change.Keygen(n("target"))
	case "key-add":
		kt := pl("key_type")
		switch kt {
		case "", "ed25519", "rsa", "ecdsa", "ed25519-sk", "ecdsa-sk":
		default:
			errs = append(errs, badForm("key type must be ed25519, rsa, ecdsa, ed25519-sk or ecdsa-sk"))
		}
		host := ""
		if strings.TrimSpace(f.Get("host")) != "" {
			host = n("host")
		}
		ch = change.KeyAdd(n("profile"), n("key"), kt, host)
	case "providers-export":
		ch = change.ProvidersExport()
	case "snapshots-prune":
		keep, err := strconv.Atoi(strings.TrimSpace(f.Get("keep")))
		if err != nil || keep < 0 || keep > 1000 {
			errs = append(errs, badForm("keep must be a number from 0 to 1000"))
		}
		ch = change.SnapshotsPrune(keep)
	case "doctor-fix":
		ch = change.DoctorFix()
	case "host-apply":
		specs, err := hostSpecs(f)
		errs = append(errs, err)
		category, err := optionalName(f, "category")
		errs = append(errs, err)
		ch = change.HostApply(n("profile"), specs, checked(f, "create"), category)
	case "clean":
		ch = change.Clean(checked(f, "adopt"))
	case "bundle":
		keep := 0
		if v := strings.TrimSpace(f.Get("keep")); v != "" {
			var err error
			if keep, err = strconv.Atoi(v); err != nil || keep < 0 || keep > 1000 {
				errs = append(errs, badForm("keep must be a number from 0 to 1000"))
			}
		}
		ch = change.Bundle(keep)
	case "vm-docker-context":
		ch = change.VMDockerContext(n("alias"))
	case "snapshots-restore":
		retain := h.retain
		if retain < 1 {
			retain = 10
		}
		ch = change.SnapshotRestore(h.p.SnapshotsDir(), n("id"), retain)
	case "notify-test":
		ch = change.NotifyTest()
	case "audit-notify":
		ch = change.AuditNotify()
	}
	return ch, errors.Join(errs...)
}

// carried is the form, cut to the fields its action reads, for the
// confirmation to post back unchanged.
func carried(f url.Values) []formField {
	out := []formField{{"action", f.Get("action")}}
	for _, k := range actionFields[f.Get("action")] {
		if f.Has(k) {
			out = append(out, formField{k, f.Get(k)})
		}
	}
	return out
}

type formField struct{ Name, Value string }

type changePage struct {
	Plan    change.Plan
	Fields  []formField
	Stale   bool
	Command string
	Destroy bool // the action removes something; the button says so
	Purge   bool // it deletes private keys too, which the page spells out
}

type donePage struct {
	Command string
	Result  change.Result
}

func commandLine(p change.Plan) string {
	return strings.TrimSpace("sshmgr " + p.Command + " " + strings.Join(p.Args, " "))
}

func (h pages) parseChange(w http.ResponseWriter, r *http.Request) (change.Change, bool) {
	if err := r.ParseForm(); err != nil {
		h.s.renderError(w, r, http.StatusBadRequest, "Unreadable form", err.Error())
		return change.Change{}, false
	}
	ch, err := buildChange(r.PostForm, home{p: h.s.opts.Engine.Home(), retain: h.s.opts.Retain})
	if err != nil {
		h.s.renderError(w, r, http.StatusBadRequest, "That change cannot be made", err.Error())
		return change.Change{}, false
	}
	return ch, true
}

func (h pages) handlePreview(w http.ResponseWriter, r *http.Request) {
	ch, ok := h.parseChange(w, r)
	if !ok {
		return
	}
	plan, err := h.s.opts.Engine.Preview(ch)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.renderChange(w, r, http.StatusOK, plan, false)
}

func (h pages) handleApply(w http.ResponseWriter, r *http.Request) {
	ch, ok := h.parseChange(w, r)
	if !ok {
		return
	}
	fresh, res, err := h.s.opts.Engine.Apply(ch, r.PostForm.Get("hash"))
	switch {
	case errors.Is(err, change.ErrStale):
		h.renderChange(w, r, http.StatusConflict, fresh, true)
	case err != nil:
		h.s.renderError(w, r, http.StatusUnprocessableEntity, "The change was not made", err.Error())
	default:
		h.s.render(w, http.StatusOK, "done", h.s.newView(r, "", "Done",
			donePage{Command: strings.TrimSpace("sshmgr " + ch.Command + " " + strings.Join(ch.Args, " ")), Result: res}))
	}
}

func (h pages) renderChange(w http.ResponseWriter, r *http.Request, status int, plan change.Plan, stale bool) {
	action := r.PostForm.Get("action")
	h.s.render(w, status, "change", h.s.newView(r, "", "Review the change", changePage{
		Plan: plan, Fields: carried(r.PostForm), Stale: stale, Command: commandLine(plan),
		Destroy: strings.HasSuffix(action, "-delete"),
		Purge:   action == "profile-delete" && checked(r.PostForm, "purge"),
	}))
}
