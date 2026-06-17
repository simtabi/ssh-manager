package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/configsvc"
	"github.com/simtabi/ssh-manager/internal/services/deployer"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
	"github.com/simtabi/ssh-manager/internal/services/notifier"
	"github.com/simtabi/ssh-manager/internal/services/query"
	"github.com/simtabi/ssh-manager/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/internal/services/rotator"
	"github.com/simtabi/ssh-manager/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/internal/util/paths"
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

func newStdinPrompter(out io.Writer) *stdinPrompter {
	return &stdinPrompter{out: out, in: bufio.NewReader(os.Stdin)}
}

func (s *stdinPrompter) Select(message string, choices []string) (string, bool) {
	fmt.Fprintln(s.out, message+":")
	for i, ch := range choices {
		fmt.Fprintf(s.out, "  %d) %s\n", i+1, ch)
	}
	fmt.Fprint(s.out, "> ")
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
	fmt.Fprintf(s.out, "%s [y/N] ", message)
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
		RunE: func(c *cobra.Command, _ []string) error {
			out := c.OutOrStdout()
			t := &tui{p: paths.Resolve(nil, "", ""), pr: newStdinPrompter(out), out: out}
			t.run()
			return nil
		},
	}
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
	out, err := configsvc.New(t.p.SSHDir, m, runtime.GOOS == "darwin").Show("")
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
	states, err := notifier.New(t.p, m.Defaults).States(time.Now())
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
	emit := runtime.GOOS == "darwin"
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
	report, err := knownhosts.New(t.p.SSHDir).Init(m, "", true, false, false)
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
	_ = inv.Save(t.p.Inventory())
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
		_ = inv.Save(t.p.Inventory())
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
	chosen, err := snapshots.RestoreByID(t.p.SSHDir, t.p.SnapshotsDir(), snapshotRetain, choice)
	if err != nil {
		t.print("error: " + err.Error())
		return
	}
	t.print("restored from " + filepath.Base(chosen))
}

func (t *tui) banner() {
	if m := t.manifest(); m != nil {
		if text := notifier.New(t.p, m.Defaults).Banner(time.Now()); text != "" {
			t.print(text)
		}
	}
}

func (t *tui) print(text string) { fmt.Fprintln(t.out, text) }

func keyNames(m *manifest.Manifest) []string {
	rks, err := m.IterResolved()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, rk := range rks {
		set[rk.KeyName] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
