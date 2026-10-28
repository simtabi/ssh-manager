package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// Every change the web offers must leave the home exactly as the CLI command
// it stands for does. Each case runs the CLI in one home and the change, through
// Preview and Apply, in an identical second home, then compares every file
// either could have written.

func ptr[T any](v T) *T { return &v }

// twinHomes builds a home by running setup through the CLI, then copies it.
func twinHomes(t *testing.T, setup [][]string) (cli, web paths.Paths) {
	t.Helper()
	cli = editHome(t)
	for _, args := range setup {
		run(t, args...)
	}
	mutation.Release()
	base := t.TempDir()
	web = paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	copyTree(t, cli.SSHDir, web.SSHDir)
	copyTree(t, cli.ConfigDir, web.ConfigDir)
	return cli, web
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// stateOf reads the files a change may write, with the home's own paths
// replaced so two homes compare equal when they hold the same thing. Two mints
// of the same key differ in their bytes, so key blobs, fingerprints and private
// key contents compare by shape: the same keys, in the same places, recorded
// the same way.
func stateOf(t *testing.T, p paths.Paths) map[string]string {
	t.Helper()
	out := map[string]string{}
	if b, err := os.ReadFile(p.Manifest()); err == nil {
		out["manifest.json"] = string(b)
	}
	if b, err := os.ReadFile(p.Providers()); err == nil {
		out["providers.json"] = string(b)
	}
	out["inventory.json"] = inventoryShape(t, p)
	// Snapshot counts are compared for prune only (see the case): the web takes
	// a snapshot before every change it makes, where the CLI's config render,
	// providers --export and doctor --fix take none.
	out["snapshots"] = fmt.Sprint(len(snapshots.List(p.SnapshotsDir())))
	bundles, _ := filepath.Glob(filepath.Join(p.DistDir(), "ssh-manager-*.age"))
	out["bundles"] = fmt.Sprint(len(bundles))
	for _, f := range []string{p.Manifest(), p.Inventory()} {
		if fi, err := os.Stat(f); err == nil {
			out["mode "+filepath.Base(f)] = fi.Mode().Perm().String()
		}
	}
	_ = filepath.Walk(p.SSHDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(p.SSHDir, path)
		key := "ssh/" + filepath.ToSlash(rel)
		if !snapshots.Archivable(fi.Name()) {
			out[key] = "<present " + fi.Mode().Perm().String() + ">"
			return nil
		}
		b, _ := os.ReadFile(path)
		out[key] = volatile(strings.ReplaceAll(string(b), p.SSHDir, "<ssh>"))
		return nil
	})
	return out
}

var (
	keyBlob     = regexp.MustCompile(`(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/=]{16,}`)
	fingerprint = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]{20,}`)
)

func volatile(s string) string {
	return fingerprint.ReplaceAllString(keyBlob.ReplaceAllString(s, "$1 <key>"), "<fingerprint>")
}

// inventoryShape is the inventory with its fingerprint keys dropped and its
// records in path order, so two homes holding different mints of the same
// keys compare equal.
func inventoryShape(t *testing.T, p paths.Paths) string {
	t.Helper()
	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		return "unreadable: " + err.Error()
	}
	var recs []string
	for _, r := range inv.Keys {
		b, _ := json.Marshal(r)
		recs = append(recs, volatile(string(b)))
	}
	sort.Strings(recs)
	return strings.Join(recs, "\n")
}

func TestEveryWebChangeMatchesItsCommand(t *testing.T) {
	setup := [][]string{
		{"profile", "add", "work"},
		{"host", "add", "work", "gh", "-H", "github.com", "-u", "git"},
		{"host", "add", "work", "db", "-H", "db.example", "-u", "ops", "--tag", "prod"},
		{"reconcile", "--yes", "--no-pin"},
		{"key", "add", "work", "spare"},
		{"host", "add", "work", "new01", "-H", "new01.example", "-u", "ops"},
	}
	// Changes that act outside the home are compared by what they did there:
	// each side gets its own stand-in docker and notifier, logging its calls.
	logs := map[string]string{}
	stubs := func(name, script string) func(t *testing.T, side string) {
		return func(t *testing.T, side string) {
			bin := t.TempDir()
			logs[side] = filepath.Join(bin, "calls.log")
			stubBin(t, bin, name, `printf '%s\n' "$*" >> "`+logs[side]+`"`+"\n"+script)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
	}
	// The web asks `docker context inspect` once per preview, so reads are
	// left out: what must match is every call that changes something.
	writes := func(side string) string {
		b, _ := os.ReadFile(logs[side])
		var keep []string
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if !strings.Contains(l, " inspect ") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	sameCalls := func(t *testing.T) {
		a, b := writes("cli"), writes("web")
		if a == "" || a != b {
			t.Errorf("the two sides made different calls:\n--- cli\n%s--- web\n%s", a, b)
		}
	}
	needsAge := func(t *testing.T, _ string) {
		if !hasAge() {
			t.Skip("age not installed")
		}
		if os.Getenv("SSH_MANAGER_AGE_RECIPIENT") == "" {
			recipient, _ := ageIdentity(t)
			t.Setenv("SSH_MANAGER_AGE_RECIPIENT", recipient)
		}
	}
	notifier := stubs("terminal-notifier", "")
	if runtime.GOOS != "darwin" {
		notifier = stubs("notify-send", "")
	}
	cases := []struct {
		name  string
		cli   []string
		ch    change.Change
		pre   func(p paths.Paths)             // applied to both homes first
		env   func(t *testing.T, side string) // before each side runs
		check func(t *testing.T)              // after both have
	}{
		{"profile add", []string{"profile", "add", "home", "--key-comment", "{profile} laptop"},
			change.ProfileAdd("home", "", "", "{profile} laptop"), nil, nil, nil},
		{"profile edit", []string{"profile", "edit", "work", "--key-scope", "shared", "--key-name", "work_all"},
			change.ProfileEdit("work", ptr("shared"), ptr("work_all")), nil, nil, nil},
		{"profile delete", []string{"profile", "delete", "work", "--yes"}, change.ProfileDelete("work"), nil, nil, nil},
		{"host add", []string{"host", "add", "work", "web", "-H", "web.example", "-u", "deploy", "-p", "2222", "--tag", "a", "--tag", "b"},
			change.HostAdd("work", "web", change.HostInput{Hostname: ptr("web.example"), User: ptr("deploy"), Port: ptr(2222),
				Tags: &[]string{"a", "b"}}), nil, nil, nil},
		{"host edit", []string{"host", "edit", "work", "db", "-u", "root", "--tag", ""},
			change.HostEdit("work", "db", change.HostInput{User: ptr("root"), Tags: &[]string{""}}), nil, nil, nil},
		{"host delete", []string{"host", "delete", "work", "db", "--yes"}, change.HostDelete("work", "db"), nil, nil, nil},
		{"key delete", []string{"key", "delete", "work/spare", "--yes"},
			change.KeyDelete(manifest.KeyRef{Profile: "work", KeyName: "spare"}), nil, nil, nil},
		{"vm add", []string{"vm", "add", "work", "devbox", "--hypervisor", "parallels", "--vm", "Ubuntu", "-u", "dev", "--yes"},
			change.VMAdd("work", "devbox", "parallels", "Ubuntu", "dev"), nil, nil, nil},
		{"config render", []string{"config", "render", "--yes"}, change.ConfigRender(), nil, nil, nil},
		{"reconcile", []string{"reconcile", "--yes", "--no-pin"}, change.Reconcile(), nil, nil, nil},
		{"keygen", []string{"keygen", "work", "--no-pin", "--yes"}, change.Keygen("work"), nil, nil, nil},
		{"key add", []string{"key", "add", "work", "extra", "--type", "ed25519", "--host", "new01"},
			change.KeyAdd("work", "extra", "ed25519", "new01"), nil, nil, nil},
		{"providers export", []string{"providers", "--export"}, change.ProvidersExport(), nil, nil, nil},
		{"snapshots prune", []string{"snapshots", "prune", "--keep", "2"}, change.SnapshotsPrune(2), nil, nil, nil},
		{"doctor fix", []string{"doctor", "--fix"}, change.DoctorFix(), func(p paths.Paths) {
			_ = os.Chmod(p.Manifest(), 0o644)
		}, nil, nil},
		{"host apply", []string{"host", "apply", "work", "--host", "db db2.example:2200 root db", "--host", "cache cache.example ops", "--yes"},
			change.HostApply("work", []editor.HostSpec{{Alias: "db", Hostname: "db2.example", Port: 2200, User: "root", Role: "db"},
				{Alias: "cache", Hostname: "cache.example", User: "ops"}}, false, ""), nil, nil, nil},
		{"host apply, new profile", []string{"host", "apply", "lab", "box", "box.example", "me", "--category", "clients", "--yes"},
			change.HostApply("lab", []editor.HostSpec{{Alias: "box", Hostname: "box.example", User: "me"}}, false, "clients"), nil, nil, nil},
		{"profile category", []string{"profile", "edit", "work", "--category", "clients"},
			change.ProfileCategory("work", "clients"), nil, nil, nil},
		{"profile purge", []string{"profile", "delete", "work", "--purge", "--yes"}, change.ProfilePurge("work"), nil, needsAge, nil},
		{"clean", []string{"clean", "--yes"}, change.Clean(false), func(p paths.Paths) {
			inv, err := inventory.Load(p.Inventory())
			if err != nil {
				return
			}
			// The same record in both homes: spare's, pointed at a key no
			// manifest entry owns.
			for fp, rec := range inv.Keys {
				if strings.HasSuffix(rec.Path, "/spare") {
					rec.Path = "~/.ssh/profiles/work/ghost-ed25519"
					inv.Keys[fp] = rec
				}
			}
			_ = inv.Save(p.Inventory())
		}, nil, nil},
		{"bundle", []string{"bundle", "--keep", "1"}, change.Bundle(1), nil, needsAge, nil},
		{"vm docker-context", []string{"vm", "docker-context", "devbox"}, change.VMDockerContext("devbox"), func(p paths.Paths) {
			m, _ := manifest.Load(p.Manifest())
			prof := m.Profiles["work"]
			prof.Hosts = append(prof.Hosts, manifest.Host{Alias: "devbox", Hostname: "devbox", User: "dev",
				VM: &manifest.VMSpec{Hypervisor: "lima", Name: "default"}})
			m.SetProfile("work", prof)
			_ = m.Save(p.Manifest())
		}, stubs("docker", `[ "$2" != inspect ]`), sameCalls},
		{"notify test", []string{"notify", "test"}, change.NotifyTest(), nil, notifier, sameCalls},
		{"audit notify", []string{"audit", "--notify"}, change.AuditNotify(), nil, notifier, nil},
	}
	if len(cases) != 24 {
		t.Fatalf("%d cases; every change the web offers needs one", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliHome, webHome := twinHomes(t, setup)
			if tc.pre != nil {
				tc.pre(cliHome)
				tc.pre(webHome)
			}
			mutation.Release()
			if tc.env != nil {
				tc.env(t, "cli")
			}
			if out, err := runIn(t, "", tc.cli...); err != nil && !errors.Is(err, errNotClean) {
				t.Fatalf("%v: %v\n%s", tc.cli, err, out)
			}
			mutation.Release()
			if tc.env != nil {
				tc.env(t, "web")
			}
			plan, err := change.Preview(webHome, tc.ch)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Err != "" {
				t.Fatalf("the preview says it would fail: %s", plan.Err)
			}
			if _, _, err := change.Apply(webHome, tc.ch, plan.Hash, 10, history.SourceWeb); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if tc.check != nil {
				tc.check(t)
			}
			a, b := stateOf(t, cliHome), stateOf(t, webHome)
			var names []string
			for k := range a {
				names = append(names, k)
			}
			for k := range b {
				if _, ok := a[k]; !ok {
					names = append(names, k)
				}
			}
			sort.Strings(names)
			if len(names) < 3 {
				t.Fatalf("compared %d files; the comparison is not reaching the homes", len(names))
			}
			for _, n := range names {
				if n == "snapshots" && tc.name != "snapshots prune" {
					continue
				}
				if a[n] != b[n] {
					t.Errorf("%s differs:\n--- cli\n%s\n--- web\n%s", n, a[n], b[n])
				}
			}
		})
	}
}
