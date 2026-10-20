package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

func gitRepo(t *testing.T, origin string) string {
	t.Helper()
	needBin(t, "git")
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	for _, args := range [][]string{{"init", "-q", dir}, {"-C", dir, "remote", "add", "origin", origin}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

func TestGitStatusAndDryRunUse(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "imanimanyara")
	run(t, "host", "add", "imanimanyara", "github-imanimanyara", "-H", "github.com", "-u", "git")
	repo := gitRepo(t, "https://github.com/simtabi/pheg.git")

	out := run(t, "git", "status", repo)
	if !strings.Contains(out, "https  simtabi/pheg  profile=imanimanyara (by owner)") {
		t.Errorf("status:\n%s", out)
	}
	out = run(t, "git", "use", "profile", repo, "--dry-run")
	if !strings.Contains(out, "would change  https://github.com/simtabi/pheg.git -> git@github-imanimanyara:simtabi/pheg.git") {
		t.Errorf("dry run:\n%s", out)
	}
	if got, _ := exec.Command("git", "-C", repo, "remote", "get-url", "origin").Output(); strings.TrimSpace(string(got)) != "https://github.com/simtabi/pheg.git" {
		t.Errorf("dry run changed origin to %s", got)
	}
	// ssh mode with no defaults.git.profile has no key bound to Host github.com: refused, not guessed.
	if _, err := runErr(t, "git", "use", "ssh", repo, "--dry-run"); err == nil {
		t.Error("ssh mode without defaults.git.profile should fail")
	}
	if out, _ := runErr(t, "git", "use", "https", t.TempDir(), "--dry-run"); !strings.Contains(out, "no origin") {
		t.Errorf("a directory with no repository is skipped and said so:\n%s", out)
	}
}

func TestGitModePrecedence(t *testing.T) {
	m := &manifest.Manifest{Defaults: manifest.Defaults{Git: &manifest.GitDefaults{Mode: "https"}}}
	t.Setenv(gitModeEnv, "")
	if got, _ := resolveGitMode("", m); got != "https" {
		t.Errorf("manifest default: %q", got)
	}
	t.Setenv(gitModeEnv, "ssh")
	if got, _ := resolveGitMode("", m); got != "ssh" {
		t.Errorf("env over manifest: %q", got)
	}
	if got, _ := resolveGitMode("profile", m); got != "profile" {
		t.Errorf("explicit over env: %q", got)
	}
	t.Setenv(gitModeEnv, "")
	if got, _ := resolveGitMode("", &manifest.Manifest{}); got != "profile" {
		t.Errorf("nothing set: %q", got)
	}
	if _, err := resolveGitMode("ftp", m); err == nil {
		t.Error("unknown mode accepted")
	}
}
