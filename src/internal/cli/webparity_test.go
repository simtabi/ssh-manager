package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/change"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
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
// replaced so two homes compare equal when they hold the same thing.
func stateOf(t *testing.T, p paths.Paths) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"manifest.json", "inventory.json"} {
		if b, err := os.ReadFile(filepath.Join(p.ConfigDir, name)); err == nil {
			out[name] = string(b)
		}
	}
	_ = filepath.Walk(p.SSHDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(p.SSHDir, path)
		b, _ := os.ReadFile(path)
		out["ssh/"+filepath.ToSlash(rel)] = strings.ReplaceAll(string(b), p.SSHDir, "<ssh>")
		return nil
	})
	return out
}

func TestEveryWebChangeMatchesItsCommand(t *testing.T) {
	setup := [][]string{
		{"profile", "add", "work"},
		{"host", "add", "work", "gh", "-H", "github.com", "-u", "git"},
		{"host", "add", "work", "db", "-H", "db.example", "-u", "ops", "--tag", "prod"},
		{"reconcile", "--yes", "--no-pin"},
		{"key", "add", "work", "spare"},
	}
	cases := []struct {
		name string
		cli  []string
		ch   change.Change
	}{
		{"profile add", []string{"profile", "add", "home", "--key-comment", "{profile} laptop"},
			change.ProfileAdd("home", "", "", "{profile} laptop")},
		{"profile edit", []string{"profile", "edit", "work", "--key-scope", "shared", "--key-name", "work_all"},
			change.ProfileEdit("work", ptr("shared"), ptr("work_all"))},
		{"profile delete", []string{"profile", "delete", "work", "--yes"}, change.ProfileDelete("work")},
		{"host add", []string{"host", "add", "work", "web", "-H", "web.example", "-u", "deploy", "-p", "2222", "--tag", "a", "--tag", "b"},
			change.HostAdd("work", "web", change.HostInput{Hostname: ptr("web.example"), User: ptr("deploy"), Port: ptr(2222),
				Tags: &[]string{"a", "b"}})},
		{"host edit", []string{"host", "edit", "work", "db", "-u", "root", "--tag", ""},
			change.HostEdit("work", "db", change.HostInput{User: ptr("root"), Tags: &[]string{""}})},
		{"host delete", []string{"host", "delete", "work", "db", "--yes"}, change.HostDelete("work", "db")},
		{"key delete", []string{"key", "delete", "work/spare", "--yes"},
			change.KeyDelete(manifest.KeyRef{Profile: "work", KeyName: "spare"})},
		{"vm add", []string{"vm", "add", "work", "devbox", "--hypervisor", "parallels", "--vm", "Ubuntu", "-u", "dev", "--yes"},
			change.VMAdd("work", "devbox", "parallels", "Ubuntu", "dev")},
		{"config render", []string{"config", "render", "--yes"}, change.ConfigRender()},
	}
	if len(cases) != 9 {
		t.Fatalf("%d cases; every change the web offers needs one", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cliHome, webHome := twinHomes(t, setup)
			mutation.Release()
			run(t, tc.cli...)
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
				if a[n] != b[n] {
					t.Errorf("%s differs:\n--- cli\n%s\n--- web\n%s", n, a[n], b[n])
				}
			}
		})
	}
}
