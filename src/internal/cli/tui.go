package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/deployer"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/notifier"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/query"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/rotator"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

const (
	tuiBack   = "<- back"
	tuiCancel = "(cancel)"
)

// prompter is the TUI's interaction seam: production reads stdin, tests inject a
// scripted fake so the navigation loop is testable without a TTY.
type prompter interface {
	Select(message string, choices []string) (string, bool) // ok=false on cancel/EOF
	Confirm(message string) bool
}

// stdinPrompter is a dependency-free numbered-menu prompter over stdin.
type stdinPrompter struct {
	out io.Writer
	in  *bufio.Reader
}

// newStdinPrompter builds the prompter over the streams it is given. Input
// comes from the caller rather than os.Stdin directly, matching how the output
// half already goes through the command: the two halves of one conversation
// should not disagree about which streams they are on, and reaching past the
// command meant the whole menu loop could only be driven by a real terminal.
func newStdinPrompter(out io.Writer, in io.Reader) *stdinPrompter {
	return &stdinPrompter{out: out, in: bufio.NewReader(in)}
}

func (s *stdinPrompter) Select(message string, choices []string) (string, bool) {
	_, _ = fmt.Fprintln(s.out, message+":")
	for i, ch := range choices {
		_, _ = fmt.Fprintf(s.out, "  %d) %s\n", i+1, ch)
	}
	_, _ = fmt.Fprint(s.out, "> ")
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(choices) {
		return "", false
	}
	return choices[n-1], true
}

func (s *stdinPrompter) Confirm(message string) bool {
	_, _ = fmt.Fprintf(s.out, "%s [y/N] ", message)
	line, _ := s.in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

type menuItem struct {
	label, handler string
}

var tuiMenu = []menuItem{
	{"Browse profiles & hosts", "browse"},
	{"Show rendered config", "show_config"},
	{"Expiry status", "expiry"},
	{"Audit (deployments + expiry)", "audit"},
	{"Reconcile (apply manifest)", "reconcile"},
	{"Pin host keys (known_hosts)", "knownhosts"},
	{"Deploy a key", "deploy"},
	{"Rotate a key", "rotate"},
	{"Snapshots (list / restore)", "snapshots"},
	{"Quit", "quit"},
}

// tui drives the interactive menu over the native services. No business logic
// lives here - every action calls a service (mirrors tui.py).
type tui struct {
	p   paths.Paths
	pr  prompter
	out io.Writer
}

func newTuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive menu over the manager",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runTUI(c) },
	}
}

// runTUI is the entry point for both `sshmgr tui` and a bare `sshmgr` on a
// terminal, so the two cannot drift into behaving differently.
func runTUI(c *cobra.Command) error {
	out := c.OutOrStdout()
	t := &tui{p: paths.Resolve(nil, "", ""), pr: newStdinPrompter(out, c.InOrStdin()), out: out}
	t.run()
	return nil
}

func (t *tui) run() {
	t.banner()
	labels := make([]string, len(tuiMenu))
	for i, m := range tuiMenu {
		labels[i] = m.label
	}
	for {
		choice, ok := t.pr.Select("ssh-manager", labels)
		if !ok {
			return
		}
		handler := ""
		for _, m := range tuiMenu {
			if m.label == choice {
				handler = m.handler
			}
		}
		if handler == "" || handler == "quit" {
			return
		}
		t.dispatch(handler)
	}
}

func (t *tui) dispatch(handler string) {
	switch handler {
	case "browse":
		t.browse()
	case "show_config":
		t.showConfig()
	case "expiry":
		t.expiry()
	case "audit":
		t.audit()
	case "reconcile":
		t.reconcile()
	case "knownhosts":
		t.knownhosts()
	case "deploy":
		t.deploy()
	case "rotate":
		t.rotate()
	case "snapshots":
		t.snapshots()
	}
}

func (t *tui) manifest() *manifest.Manifest {
	m, err := manifest.Load(t.p.Manifest())
	if err != nil {
		return nil
	}
	return m
}

func (t *tui) query() (*query.Query, *manifest.Manifest) {
	m := t.manifest()
	if m == nil {
		return nil, nil
	}
	inv, _ := inventory.Load(t.p.Inventory())
	return query.New(m, inv, t.p.Providers()), m
}

func (t *tui) browse() {
	m := t.manifest()
	if m == nil || len(m.Profiles) == 0 {
		t.print("no profiles - run init / edit the manifest")
		return
	}
	p, ok := t.pr.Select("Profile", append(m.ProfileNames(), tuiBack))
	if !ok || p == tuiBack {
		return
	}
	t.view(p)
	var aliases []string
	for _, h := range m.Profiles[p].Hosts {
		aliases = append(aliases, h.Alias)
	}
	if len(aliases) > 0 {
		h, ok := t.pr.Select("Host", append(aliases, tuiBack))
		if ok && h != tuiBack {
			t.view(h)
		}
	}
}

func (t *tui) view(selector string) {
	q, _ := t.query()
	if q == nil {
		t.print("no manifest")
		return
	}
	d, err := q.Detail(selector)
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	switch v := d.(type) {
	case *query.ProfileSummary:
		renderProfileSummary(t.out, v)
	case *query.HostDetail:
		renderHostDetail(t.out, v)
	}
}

func (t *tui) showConfig() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	out, err := configsvc.New(t.p.SSHDir, m, platform.EmitUseKeychain()).Show("")
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print(out)
}

func (t *tui) expiry() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	states, err := notifier.New(t.p, m).States(time.Now())
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	writeExpiryTable(t.out, states)
}

func (t *tui) audit() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	report, err := auditReport(t.p, m, time.Now(), false)
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print(report)
}

func (t *tui) reconcile() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	inv, _ := inventory.Load(t.p.Inventory())
	emit := platform.EmitUseKeychain()
	dry, err := reconciler.New(t.p, m, inv, emit).Reconcile(true, "")
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print(dry.Format())
	if !t.pr.Confirm("Apply these changes to ~/.ssh?") {
		return
	}
	snapshotBeforeMutation(t.p)
	inv2, _ := inventory.Load(t.p.Inventory())
	res, err := reconciler.New(t.p, m, inv2, emit).Reconcile(false, "")
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	if len(res.Minted) > 0 {
		res.Pinned = knownhosts.New(t.p.SSHDir).AutoPin(m, nil, os.Getenv)
	}
	t.print(res.Format())
}

func (t *tui) knownhosts() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	snapshotBeforeMutation(t.p)
	report, err := knownhosts.New(t.p.SSHDir).Init(m, "", true, false)
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print(report.Format())
}

func (t *tui) deploy() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	keys := keyNames(m)
	if len(keys) == 0 {
		t.print("no keys yet - reconcile first")
		return
	}
	k, ok := t.pr.Select("Key to deploy", append(keys, tuiBack))
	if !ok || k == tuiBack {
		return
	}
	inv, _ := inventory.Load(t.p.Inventory())
	report, err := deployer.New(t.p, m, inv).Deploy(k, "")
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	// A swallowed save is a deploy that happened remotely and is recorded
	// nowhere: audit keeps saying needs-redeploy and nobody knows why.
	if err := inv.Save(t.p.Inventory()); err != nil {
		t.print("WARNING: the key was deployed but the inventory could not be saved: " + err.Error())
	}
	t.print(report.Format())
}

func (t *tui) rotate() {
	m := t.manifest()
	if m == nil {
		t.print("no manifest")
		return
	}
	keys := keyNames(m)
	if len(keys) == 0 {
		t.print("no keys yet - reconcile first")
		return
	}
	k, ok := t.pr.Select("Key to rotate", append(keys, tuiBack))
	if !ok || k == tuiBack {
		return
	}
	if !t.pr.Confirm(fmt.Sprintf("Rotate %s? (destructive; ~/.ssh snapshotted first)", k)) {
		t.print("cancelled")
		return
	}
	snapshotBeforeMutation(t.p)
	inv, _ := inventory.Load(t.p.Inventory())
	report, err := rotator.New(t.p, m, inv).Rotate(k, false, "")
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	if report.Committed {
		if err := inv.Save(t.p.Inventory()); err != nil {
			t.print("WARNING: the rotation completed but the inventory could not be saved: " + err.Error())
		}
	}
	t.print(report.Format())
}

func (t *tui) snapshots() {
	snaps := snapshots.List(t.p.SnapshotsDir())
	if len(snaps) == 0 {
		t.print("no snapshots yet")
		return
	}
	names := []string{tuiCancel}
	for _, s := range snaps {
		names = append(names, filepath.Base(s))
	}
	choice, ok := t.pr.Select("Restore which snapshot?", names)
	if !ok || choice == tuiCancel {
		return
	}
	if !t.pr.Confirm(fmt.Sprintf("Restore %s? (current tree snapshotted first)", choice)) {
		return
	}
	chosen, err := snapshots.RestoreByID(t.p.SSHDir, t.p.SnapshotsDir(), snapshotRetain(), choice)
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print("restored from " + filepath.Base(chosen))
}

func (t *tui) banner() {
	if m := t.manifest(); m != nil {
		if text := notifier.New(t.p, m).Banner(time.Now()); text != "" {
			t.print(text)
		}
	}
}

func (t *tui) print(text string) { _, _ = fmt.Fprintln(t.out, text) }

// keyNames lists keys as "profile/key" selectors. The composite form is used
// even when a name is unique, so the picker never hides which profile a key
// belongs to when the same person's name appears under several orgs.
func keyNames(m *manifest.Manifest) []string {
	refs, err := m.KeyRefs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.String())
	}
	sort.Strings(out)
	return out
}
