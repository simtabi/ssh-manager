package gitremote

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

const fixture = `{
  "version": 1,
  "defaults": {"git": {"profile": "imanimanyara", "orgs": {"adelsaiq": "dannielagumo"}}},
  "profiles": {
    "imanimanyara": {"hosts": [{"alias": "github-imanimanyara", "hostname": "github.com", "user": "git", "key_name": "imanimanyara_github-ed25519"}]},
    "dannielagumo": {"hosts": [{"alias": "github-dannielagumo", "hostname": "github.com", "user": "git", "key_name": "dannielagumo_github-ed25519"}]},
    "unc": {"hosts": [{"alias": "unc", "hostname": "sc.its.unc.edu", "user": "git", "key_name": "unc_git-ed25519"}]}
  }
}`

func load(t *testing.T, s string) *manifest.Manifest {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParse(t *testing.T) {
	m := load(t, fixture)
	cases := []struct {
		url                        string
		ok                         bool
		mode, owner, repo, profile string
	}{
		{"https://github.com/simtabi/ssh-manager.git", true, "https", "simtabi", "ssh-manager", ""},
		{"https://github.com/simtabi/ssh-manager", true, "https", "simtabi", "ssh-manager", ""},
		{"https://x-access-token@github.com/simtabi/osaat.git", true, "https", "simtabi", "osaat", ""},
		{"git@github.com:laranail/emojis.git", true, "ssh", "laranail", "emojis", ""},
		{"ssh://git@github.com/laranail/emojis.git", true, "ssh", "laranail", "emojis", ""},
		{"git@github-imanimanyara:simtabi/pheg.git", true, "profile", "simtabi", "pheg", "imanimanyara"},
		{"git@github-dannielagumo:adelsaiq/app.git", true, "profile", "adelsaiq", "app", "dannielagumo"},
		// Not GitHub: an alias for another host, an unknown alias, GitLab.
		{"git@unc:group/project.git", false, "", "", "", ""},
		{"git@github-nobody:simtabi/x.git", false, "", "", "", ""},
		{"https://gitlab.com/group/project.git", false, "", "", "", ""},
	}
	for _, c := range cases {
		r, ok := Parse(m, c.url)
		if ok != c.ok || (ok && (r.Mode != c.mode || r.Owner != c.owner || r.Repo != c.repo || r.Profile != c.profile)) {
			t.Errorf("Parse(%s) = %+v, %v", c.url, r, ok)
		}
	}
}

func TestURLFor(t *testing.T) {
	m := load(t, fixture)
	for mode, want := range map[string]string{
		"https":   "https://github.com/simtabi/pheg.git",
		"ssh":     "git@github.com:simtabi/pheg.git",
		"profile": "git@github-imanimanyara:simtabi/pheg.git",
	} {
		if got, err := URLFor(m, mode, "simtabi", "pheg", "imanimanyara"); err != nil || got != want {
			t.Errorf("%s: %q, %v", mode, got, err)
		}
	}
	if _, err := URLFor(m, "profile", "simtabi", "pheg", "unc"); err == nil {
		t.Error("a profile with no github.com host has no alias to use")
	}
	noGit := load(t, strings.Replace(fixture, `"defaults": {"git": {"profile": "imanimanyara", "orgs": {"adelsaiq": "dannielagumo"}}},`, "", 1))
	if _, err := URLFor(noGit, "ssh", "simtabi", "pheg", ""); err == nil || !strings.Contains(err.Error(), "defaults.git.profile") {
		t.Errorf("ssh mode without a bound key: %v", err)
	}
}

type fakeGit struct {
	origin  string
	lsErr   error
	set     string
	lsCalls int
}

func (f *fakeGit) Origin(string) (string, error) {
	if f.origin == "" {
		return "", errors.New("no origin")
	}
	return f.origin, nil
}
func (f *fakeGit) LsRemote(string, string) error { f.lsCalls++; return f.lsErr }
func (f *fakeGit) SetOrigin(_, url string) error { f.set = url; return nil }

func TestUseProvesTheURLBeforeRewriting(t *testing.T) {
	m := load(t, fixture)
	g := &fakeGit{origin: "https://github.com/adelsaiq/app.git"}
	ch, err := Use(g, m, "/r", "profile", "", false)
	if err != nil || !ch.Applied || g.set != "git@github-dannielagumo:adelsaiq/app.git" {
		t.Fatalf("ch=%+v err=%v set=%q: adelsaiq maps to dannielagumo", ch, err, g.set)
	}

	g = &fakeGit{origin: "https://github.com/simtabi/pheg.git", lsErr: errors.New("Permission denied (publickey)")}
	_, err = Use(g, m, "/r", "profile", "", false)
	if err == nil || g.set != "" || !strings.Contains(err.Error(), "origin left as") {
		t.Fatalf("a URL that fails ls-remote must not be written: err=%v set=%q", err, g.set)
	}
}

func TestUseDryRunAndNoOps(t *testing.T) {
	m := load(t, fixture)
	g := &fakeGit{origin: "https://github.com/simtabi/pheg.git"}
	ch, err := Use(g, m, "/r", "ssh", "", true)
	if err != nil || ch.Applied || ch.To != "git@github.com:simtabi/pheg.git" || g.lsCalls != 0 || g.set != "" {
		t.Fatalf("dry run touched something: ch=%+v err=%v ls=%d set=%q", ch, err, g.lsCalls, g.set)
	}
	g = &fakeGit{origin: "git@github.com:simtabi/pheg.git"}
	if ch, _ := Use(g, m, "/r", "ssh", "", false); ch.Skipped != "already ssh" || g.lsCalls != 0 {
		t.Errorf("same mode: %+v", ch)
	}
	g = &fakeGit{origin: "git@unc:group/project.git"}
	if ch, _ := Use(g, m, "/r", "https", "", false); !strings.Contains(ch.Skipped, "not a GitHub remote") {
		t.Errorf("non-GitHub origin: %+v", ch)
	}
	g = &fakeGit{}
	if ch, _ := Use(g, m, "/r", "https", "", false); !strings.Contains(ch.Skipped, "no origin") {
		t.Errorf("no origin: %+v", ch)
	}
	g = &fakeGit{origin: "https://github.com/simtabi/pheg.git"}
	if ch, err := Use(g, m, "/r", "profile", "dannielagumo", true); err != nil || ch.To != "git@github-dannielagumo:simtabi/pheg.git" {
		t.Errorf("--profile overrides the owner map: %+v %v", ch, err)
	}
}

// The real git binary, against a local repository: no network.
func TestExecReadsAndWritesOrigin(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "remote", "add", "origin", "https://github.com/simtabi/pheg.git").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	var g Exec
	if got, err := g.Origin(dir); err != nil || got != "https://github.com/simtabi/pheg.git" {
		t.Fatalf("Origin = %q, %v", got, err)
	}
	if err := g.SetOrigin(dir, "git@github-imanimanyara:simtabi/pheg.git"); err != nil {
		t.Fatal(err)
	}
	if got, _ := g.Origin(dir); got != "git@github-imanimanyara:simtabi/pheg.git" {
		t.Errorf("after SetOrigin: %q", got)
	}
	if _, err := g.Origin(t.TempDir()); err == nil {
		t.Error("a directory that is not a repository has no origin")
	}
}
