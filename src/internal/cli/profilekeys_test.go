package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// G8: profile add takes the same --key-scope profile edit does; --shared still
// works, deprecated, and the two cannot disagree.
func TestProfileAddKeyScope(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "team", "--key-scope", "shared", "--key-name", "team-ed25519")
	out := run(t, "profile", "add", "old", "--shared", "--key-name", "old-ed25519")
	if !strings.Contains(out, "deprecated") || !strings.Contains(out, "--key-scope shared") {
		t.Errorf("--shared should say it is deprecated and name its replacement:\n%s", out)
	}
	run(t, "profile", "add", "plain")
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"team": "shared", "old": "shared", "plain": "per_service"} {
		if got := m.Profiles[name].KeyScope; got != want {
			t.Errorf("%s: key_scope %q, want %q", name, got, want)
		}
	}
	if _, err := runErr(t, "profile", "add", "clash", "--shared", "--key-scope", "per_service"); err == nil {
		t.Error("--shared with --key-scope per_service should be refused")
	}
	if _, err := runErr(t, "profile", "add", "bad", "--key-scope", "everything"); err == nil {
		t.Error("an unknown --key-scope should be refused")
	}
}

// G9: naming a git host is enough; --include-git only widens the list.
func TestTermiusKeysFindsANamedGitHost(t *testing.T) {
	_, clip := termiusKeysHome(t)
	out, err := runErr(t, "termius", "keys", "github-me")
	if err != nil && strings.Contains(err.Error(), "no exported host") {
		t.Fatalf("a named git host should be found without --include-git: %v\n%s", err, out)
	}
	if strings.Contains(run(t, "termius", "keys"), "github-me") {
		t.Error("the list should still leave git hosts out without --include-git")
	}
	if _, err := runErr(t, "termius", "keys", "github-me", "--skip", "github-me"); err == nil ||
		!strings.Contains(err.Error(), "no exported host") {
		t.Errorf("--skip should still leave the host out: %v", err)
	}
	_ = clip
}

// G11: key_comment is a template on the profile (or the defaults), validated on
// load and written by ssh-keygen when the key is minted.
func TestProfileKeyComment(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	p := editHome(t)
	run(t, "profile", "add", "work", "--key-comment", "imani-{device}-{date}")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "reconcile", "--yes", "--no-pin")
	b, err := os.ReadFile(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(` imani-[a-z0-9_-]+-\d{4}-\d{2}-\d{2}\n?$`).Match(b) {
		t.Errorf("the .pub should carry the profile's key_comment: %q", b)
	}

	// A profile without one keeps the comment every release has written.
	run(t, "profile", "add", "home")
	run(t, "host", "add", "home", "box", "-H", "box.example", "-u", "me")
	run(t, "reconcile", "--yes", "--no-pin")
	b, err = os.ReadFile(filepath.Join(p.SSHDir, "profiles", "home", "home_box-ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(` home/box \d{4}-\d{2}-\d{2}\n?$`).Match(b) {
		t.Errorf("the default comment changed: %q", b)
	}

	if _, err := runErr(t, "profile", "edit", "work", "--key-comment", "{user}@{device}"); err == nil {
		t.Error("an unknown placeholder should be refused")
	}
	run(t, "profile", "edit", "work", "--key-comment", "")
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if m.Profiles["work"].KeyComment != "" || manifest.KeyCommentTemplate(m, "work") != manifest.DefaultKeyComment {
		t.Errorf("--key-comment \"\" should return the profile to the default: %q", m.Profiles["work"].KeyComment)
	}
}
