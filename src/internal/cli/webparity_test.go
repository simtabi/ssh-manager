package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
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
	cases := []struct {
		name string
		cli  []string
		ch   change.Change
		pre  func(p paths.Paths) // applied to both homes first
	}{
		{"profile add", []string{"profile", "add", "home", "--key-comment", "{profile} laptop"},
			change.ProfileAdd("home", "", "", "{profile} laptop"), nil},
		{"profile edit", []string{"profile", "edit", "work", "--key-scope", "shared", "--key-name", "work_all"},
			change.ProfileEdit("work", ptr("shared"), ptr("work_all")), nil},
		{"profile delete", []string{"profile", "delete", "work", "--yes"}, change.ProfileDelete("work"), nil},
		{"host add", []string{"host", "add", "work", "web", "-H", "web.example", "-u", "deploy", "-p", "2222", "--tag", "a", "--tag", "b"},
			change.HostAdd("work", "web", change.HostInput{Hostname: ptr("web.example"), User: ptr("deploy"), Port: ptr(2222),
				Tags: &[]string{"a", "b"}}), nil},
		{"host edit", []string{"host", "edit", "work", "db", "-u", "root", "--tag", ""},
			change.HostEdit("work", "db", change.HostInput{User: ptr("root"), Tags: &[]string{""}}), nil},
		{"host delete", []string{"host", "delete", "work", "db", "--yes"}, change.HostDelete("work", "db"), nil},
		{"key delete", []string{"key", "delete", "work/spare", "--yes"},
			change.KeyDelete(manifest.KeyRef{Profile: "work", KeyName: "spare"}), nil},
		{"vm add", []string{"vm", "add", "work", "devbox", "--hypervisor", "parallels", "--vm", "Ubuntu", "-u", "dev", "--yes"},
			change.VMAdd("work", "devbox", "parallels", "Ubuntu", "dev"), nil},
		{"config render", []string{"config", "render", "--yes"}, change.ConfigRender(), nil},
		{"reconcile", []string{"reconcile", "--yes", "--no-pin"}, change.Reconcile(), nil},
		{"keygen", []string{"keygen", "work", "--no-pin", "--yes"}, change.Keygen("work"), nil},
		{"key add", []string{"key", "add", "work", "extra", "--type", "ed25519", "--host", "new01"},
			change.KeyAdd("work", "extra", "ed25519", "new01"), nil},
		{"providers export", []string{"providers", "--export"}, change.ProvidersExport(), nil},
		{"snapshots prune", []string{"snapshots", "prune", "--keep", "2"}, change.SnapshotsPrune(2), nil},
		{"doctor fix", []string{"doctor", "--fix"}, change.DoctorFix(), func(p paths.Paths) {
			_ = os.Chmod(p.Manifest(), 0o644)
		}},
	}
	if len(cases) != 15 {
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
			if out, err := runIn(t, "", tc.cli...); err != nil && !errors.Is(err, errNotClean) {
				t.Fatalf("%v: %v\n%s", tc.cli, err, out)
			}
			mutation.Release()
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
