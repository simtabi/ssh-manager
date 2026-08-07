package providers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Parity reference: v1's github adapter and
// v1's GitLab adapter. The rule those files call out explicitly is the one tested hardest
// here: removal matches on the key *body*, never on the title, so a rotation
// cannot revoke the key it just installed when old and new share a
// filename-derived title.
//
// The CLIs are exercised through a stand-in on PATH rather than by injecting the
// exec, so argv, the environment overlay and the JSON parsing are all real.

// fakeCLI installs an executable named `name` that records every invocation and
// answers `api user/keys` with listJSON. It returns the path of the call log.
func fakeCLI(t *testing.T, name, listJSON string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.log")
	// printf only, no cat: the stand-in has to work whatever PATH the test sets,
	// and an external command would not be found once PATH points here.
	body := strings.ReplaceAll(listJSON, "'", `'\''`)
	script := `#!/bin/sh
{
  printf 'ARGV:'
  for a in "$@"; do printf ' [%s]' "$a"; done
  printf '\n'
  printf 'ENV: GH_HOST=%s GH_TOKEN=%s GH_ENTERPRISE_TOKEN=%s GITLAB_HOST=%s GITLAB_TOKEN=%s\n' \
    "$GH_HOST" "$GH_TOKEN" "$GH_ENTERPRISE_TOKEN" "$GITLAB_HOST" "$GITLAB_TOKEN"
} >> "` + calls + `"
case "$*" in
  *"--method DELETE"*) exit 0 ;;
  *"api --paginate user/keys"*) printf '%s\n' '` + body + `' ; exit 0 ;;
  *"ssh-key add"*) exit 0 ;;
esac
exit 0
`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Prepended, not replacing: a stand-in that shadows the real CLI is the
	// point, but the shell still needs an ordinary environment.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func callLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func vcsTarget(t *testing.T, pub string) Target {
	t.Helper()
	p := filepath.Join(t.TempDir(), "work_gh-ed25519.pub")
	if err := os.WriteFile(p, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Target{Alias: "gh", Hostname: "github.com", User: "git",
		PubkeyPath: p, PubkeyText: pub}
}

func TestGitHubDeployAddsAndIsIdempotent(t *testing.T) {
	pub := pubKey("g")
	t.Run("absent -> added with our title", func(t *testing.T) {
		calls := fakeCLI(t, "gh", `[]`)
		t.Setenv("GH_TOKEN", "tok")

		out := GitHub{}.Deploy(vcsTarget(t, pub))
		if !out.Verified || out.Error {
			t.Fatalf("deploy should succeed: %+v", out)
		}
		if out.Method != "github-gh" {
			t.Errorf("method = %q", out.Method)
		}
		log := callLog(t, calls)
		if !strings.Contains(log, "[ssh-key] [add]") {
			t.Errorf("expected an ssh-key add call:\n%s", log)
		}
		if !strings.Contains(log, "[--title] [ssh-manager work_gh-ed25519.pub]") {
			t.Errorf("title should be derived from the key filename:\n%s", log)
		}
	})

	t.Run("already on the account -> no second add", func(t *testing.T) {
		calls := fakeCLI(t, "gh", `[{"id":1,"key":"`+pub+`","title":"whatever"}]`)
		t.Setenv("GH_TOKEN", "tok")

		out := GitHub{}.Deploy(vcsTarget(t, pub))
		if !out.Verified || out.Detail != "already present" {
			t.Fatalf("an existing key is a success, not a re-add: %+v", out)
		}
		if strings.Contains(callLog(t, calls), "[ssh-key] [add]") {
			t.Error("a key already on the account must not be added again")
		}
	})
}

// The rule v1 file names in its own docstring. Two keys, one of them
// ours; removal must delete the matching body and leave the other alone, even
// though both carry the same title.
func TestRemoveMatchesBodyNeverTitle(t *testing.T) {
	ours, theirs := pubKey("h"), pubKey("i")
	list := `[{"id":11,"key":"` + theirs + `","title":"ssh-manager work_gh-ed25519.pub"},
	          {"id":22,"key":"` + ours + `","title":"ssh-manager work_gh-ed25519.pub"}]`

	calls := fakeCLI(t, "gh", list)
	t.Setenv("GH_TOKEN", "tok")

	if !(GitHub{}).Remove(vcsTarget(t, ours)) {
		t.Fatal("remove should find our key")
	}
	log := callLog(t, calls)
	if !strings.Contains(log, "[user/keys/22]") {
		t.Errorf("should have deleted the id whose body matches:\n%s", log)
	}
	if strings.Contains(log, "[user/keys/11]") {
		t.Error("deleted a key that only shared our title - this is the rotation footgun")
	}
}

// A GHES host selects a different token variable, and passes the host through
// GH_HOST because gh has no --hostname flag.
func TestGitHubEnterpriseUsesTheEnterpriseToken(t *testing.T) {
	pub := pubKey("j")

	t.Run("github.com uses GH_TOKEN", func(t *testing.T) {
		calls := fakeCLI(t, "gh", `[]`)
		t.Setenv("GH_TOKEN", "dotcom-token")
		GitHub{}.Deploy(vcsTarget(t, pub))

		log := callLog(t, calls)
		if !strings.Contains(log, "GH_HOST=github.com") {
			t.Errorf("GH_HOST not set:\n%s", log)
		}
		if !strings.Contains(log, "GH_TOKEN=dotcom-token") || strings.Contains(log, "GH_ENTERPRISE_TOKEN=dotcom-token") {
			t.Errorf("github.com should authenticate with GH_TOKEN:\n%s", log)
		}
	})

	t.Run("a GHES host uses GH_ENTERPRISE_TOKEN", func(t *testing.T) {
		calls := fakeCLI(t, "gh", `[]`)
		t.Setenv("GHES_TOKEN", "ghes-token")
		gh := GitHub{spec: Spec{Host: "github.example.com", TokenEnv: "GHES_TOKEN"}}
		gh.Deploy(vcsTarget(t, pub))

		log := callLog(t, calls)
		if !strings.Contains(log, "GH_HOST=github.example.com") {
			t.Errorf("GH_HOST should carry the enterprise host:\n%s", log)
		}
		if !strings.Contains(log, "GH_ENTERPRISE_TOKEN=ghes-token") {
			t.Errorf("a GHES host authenticates with GH_ENTERPRISE_TOKEN:\n%s", log)
		}
	})
}

// No token, or no CLI, is not a failure: it is the manual route.
func TestVCSFallsBackToManual(t *testing.T) {
	pub := pubKey("k")

	t.Run("no token", func(t *testing.T) {
		fakeCLI(t, "gh", `[]`)
		t.Setenv("GH_TOKEN", "")
		out := GitHub{}.Deploy(vcsTarget(t, pub))
		if out.Method != "manual" || out.Error {
			t.Errorf("want a manual fallback, got %+v", out)
		}
	})

	t.Run("no CLI on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		t.Setenv("GH_TOKEN", "tok")
		out := GitHub{}.Deploy(vcsTarget(t, pub))
		if out.Method != "manual" || out.Error {
			t.Errorf("want a manual fallback, got %+v", out)
		}
	})
}

// An API failure must not read as "the account has no keys" - that would make
// verify report false and deploy add a duplicate.
func TestListFailureIsNotAnEmptyAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	// A gh that always fails, the way an expired token behaves.
	if err := os.WriteFile(filepath.Join(dir, "gh"),
		[]byte("#!/bin/sh\necho 'HTTP 401' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("GH_TOKEN", "expired")

	target := vcsTarget(t, pubKey("l"))
	if (GitHub{}).Verify(target) {
		t.Error("verify must be false when the account cannot be listed")
	}
	if (GitHub{}).Remove(target) {
		t.Error("remove must not report success when the list failed")
	}
	if out := (GitHub{}).Deploy(target); !out.Error {
		t.Errorf("a failed add should surface as an error: %+v", out)
	}
}

func TestGitLabMirrorsGitHub(t *testing.T) {
	pub := pubKey("m")

	t.Run("deploy adds via glab", func(t *testing.T) {
		calls := fakeCLI(t, "glab", `[]`)
		t.Setenv("GLAB_TOKEN", "tok")

		out := GitLab{}.Deploy(vcsTarget(t, pub))
		if !out.Verified || out.Method != "gitlab-glab" {
			t.Fatalf("deploy: %+v", out)
		}
		log := callLog(t, calls)
		if !strings.Contains(log, "[ssh-key] [add]") {
			t.Errorf("expected an ssh-key add:\n%s", log)
		}
		// glab reads GITLAB_TOKEN/GITLAB_HOST, not GLAB_*.
		if !strings.Contains(log, "GITLAB_TOKEN=tok") || !strings.Contains(log, "GITLAB_HOST=gitlab.com") {
			t.Errorf("glab environment not set as glab expects it:\n%s", log)
		}
	})

	t.Run("remove matches on body", func(t *testing.T) {
		ours, theirs := pubKey("n"), pubKey("o")
		calls := fakeCLI(t, "glab", `[{"id":5,"key":"`+theirs+`","title":"t"},{"id":6,"key":"`+ours+`","title":"t"}]`)
		t.Setenv("GLAB_TOKEN", "tok")

		if !(GitLab{}).Remove(vcsTarget(t, ours)) {
			t.Fatal("remove should find our key")
		}
		log := callLog(t, calls)
		if !strings.Contains(log, "[user/keys/6]") || strings.Contains(log, "[user/keys/5]") {
			t.Errorf("removed the wrong key:\n%s", log)
		}
	})
}

// ManageURL is what the manual fallback shows the user, so it has to point at
// the right instance for a self-hosted host.
func TestManageURLFollowsTheHost(t *testing.T) {
	if got := (GitHub{}).ManageURL(Target{}); got != "https://github.com/settings/keys" {
		t.Errorf("github.com URL = %q", got)
	}
	ghes := GitHub{spec: Spec{Host: "github.example.com"}}
	if got := ghes.ManageURL(Target{}); !strings.Contains(got, "github.example.com") {
		t.Errorf("GHES URL = %q, should point at the instance", got)
	}
	if got := (GitLab{}).ManageURL(Target{}); !strings.Contains(got, "gitlab.com") {
		t.Errorf("gitlab URL = %q", got)
	}
	self := GitLab{spec: Spec{Host: "git.example.org"}}
	if got := self.ManageURL(Target{}); !strings.Contains(got, "git.example.org") {
		t.Errorf("self-hosted GitLab URL = %q", got)
	}
}
