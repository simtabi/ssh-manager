package renderer

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

const gitVMJSON = `{
  "version": 1,
  "defaults": {"git": {"profile": "imanimanyara"}},
  "profiles": {
    "imanimanyara": {"hosts": [
      {"alias": "github-imanimanyara", "hostname": "github.com", "user": "git", "key_name": "imanimanyara_github-ed25519"}]},
    "devbox": {"hosts": [
      {"alias": "devbox", "hostname": "devbox", "user": "imani", "key_name": "devbox_docker-ed25519",
       "vm": {"hypervisor": "parallels", "name": "Ubuntu 24.04"}}]}
  }
}`

func pinSelf(t *testing.T, path string) {
	t.Helper()
	old := SelfPath
	SelfPath = func() string { return path }
	t.Cleanup(func() { SelfPath = old })
}

func TestGitHubBlockRendersBeforeHostStar(t *testing.T) {
	pinSelf(t, "/opt/homebrew/bin/sshmgr")
	out, err := RenderRootConfig(mustManifest(t, gitVMJSON), false)
	if err != nil {
		t.Fatal(err)
	}
	gh := strings.Index(out, "Host github.com\n")
	star := strings.Index(out, "Host *\n")
	if gh < 0 || star < 0 || gh > star {
		t.Fatalf("Host github.com must exist and precede Host * (gh=%d star=%d):\n%s", gh, star, out)
	}
	block := out[gh:star]
	for _, want := range []string{"HostName github.com", "User git",
		"IdentityFile ~/.ssh/profiles/imanimanyara/imanimanyara_github-ed25519", "IdentitiesOnly yes"} {
		if !strings.Contains(block, want) {
			t.Errorf("Host github.com block lacks %q:\n%s", want, block)
		}
	}
}

func TestNoGitProfileMeansNoGitHubBlock(t *testing.T) {
	out, err := RenderRootConfig(mustManifest(t, strings.Replace(gitVMJSON, `"git": {"profile": "imanimanyara"}`, `"git": {}`, 1)), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Host github.com\n") {
		t.Errorf("rendered Host github.com without defaults.git.profile:\n%s", out)
	}
}

func TestVMHostGetsSshmgrProxyCommandAndOthersDoNot(t *testing.T) {
	pinSelf(t, "/opt/homebrew/bin/sshmgr")
	out, err := RenderRootConfig(mustManifest(t, gitVMJSON), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `    ProxyCommand "/opt/homebrew/bin/sshmgr" vm proxy devbox`+"\n") {
		t.Errorf("devbox lacks the sshmgr ProxyCommand:\n%s", out)
	}
	if n := strings.Count(out, "ProxyCommand"); n != 1 {
		t.Errorf("%d ProxyCommand lines, want 1 (only the VM host)", n)
	}
}

func TestProxyCommandQuoting(t *testing.T) {
	pinSelf(t, `C:\Program Files\sshmgr\sshmgr.exe`)
	got := ProxyCommandFor("devbox")
	if got != `"C:\Program Files\sshmgr\sshmgr.exe" vm proxy devbox` {
		t.Errorf("backslashes must stay single (ssh does not unescape): %s", got)
	}
	if ProxyBinary(got) != `C:\Program Files\sshmgr\sshmgr.exe` {
		t.Errorf("ProxyBinary(%s) = %q", got, ProxyBinary(got))
	}
	pinSelf(t, `/weird"dir/sshmgr`)
	if got := ProxyCommandFor("devbox"); got != `"sshmgr" vm proxy devbox` {
		t.Errorf("a path with a quote must fall back to the bare name: %s", got)
	}
	if ProxyBinary("ssh -W %h:%p jump") != "" {
		t.Error("a foreign ProxyCommand is not sshmgr's")
	}
}

// Pinned against OpenSSH: plain github.com resolves to the configured key, and the VM alias to the
// sshmgr ProxyCommand.
func TestSSHResolvesGitHubAndTheVMProxy(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh client")
	}
	if runtime.GOOS == "windows" {
		t.Skip("covered on Linux and macOS")
	}
	pinSelf(t, "/usr/local/bin/sshmgr")
	out, err := RenderRootConfig(mustManifest(t, gitVMJSON), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(cfg, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	get := func(alias, key string) string {
		b, err := exec.Command("ssh", "-G", "-F", cfg, alias).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G %s: %v\n%s", alias, err, b)
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(ln, " "); ok && k == key {
				return v
			}
		}
		return ""
	}
	if got := get("github.com", "identityfile"); !strings.HasSuffix(got, "/profiles/imanimanyara/imanimanyara_github-ed25519") {
		t.Errorf("github.com identityfile = %q", got)
	}
	if got := get("devbox", "proxycommand"); !strings.Contains(got, "/usr/local/bin/sshmgr") || !strings.Contains(got, "vm proxy devbox") {
		t.Errorf("devbox proxycommand = %q", got)
	}
}

func TestOrbStackIncludeIsHoistedToTheTop(t *testing.T) {
	managed := ManagedHeader + "\nHost *\n    HashKnownHosts yes\n" + ManagedEnd + "\n"
	orb := "# Added by OrbStack: 'orb' SSH host for Linux machines\n" +
		"# This only works if it's at the top of ssh_config (before any Host blocks).\n" +
		"Include ~/.orbstack/ssh/config\n"
	existing := "Host mine\n    HostName x\n\n" + managed + "\n" + orb + "\n# keep me\n"
	out := ComposeRootConfig(existing, managed)
	if !strings.HasPrefix(out, orb) {
		t.Fatalf("OrbStack include not first:\n%s", out)
	}
	if strings.Count(out, "Include ~/.orbstack") != 1 || !strings.Contains(out, "# keep me") ||
		!strings.Contains(out, "Host mine") {
		t.Fatalf("content lost or duplicated:\n%s", out)
	}
	if again := ComposeRootConfig(out, managed); again != out {
		t.Fatalf("not idempotent:\n%s\n---\n%s", out, again)
	}
}

// A git profile filed under a category renders its github.com block in that
// category's file only - it used to land in the root config as well.
func TestGitHubBlockFollowsItsProfilesCategory(t *testing.T) {
	js := strings.Replace(gitVMJSON, `"imanimanyara": {"hosts"`, `"imanimanyara": {"category": "personal", "hosts"`, 1)
	m := mustManifest(t, js)
	all, err := RenderAll(m, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(all[RootConfig], "Host github.com\n") {
		t.Errorf("root config still carries Host github.com:\n%s", all[RootConfig])
	}
	cat := all[manifest.CategoryConfigRel("personal")]
	if n := strings.Count(cat, "Host github.com\n"); n != 1 {
		t.Errorf("personal config has %d Host github.com blocks, want 1:\n%s", n, cat)
	}
	total := 0
	for _, c := range all {
		total += strings.Count(c, "Host github.com\n")
	}
	if total != 1 {
		t.Errorf("Host github.com rendered %d times across files, want 1", total)
	}
	// Still ahead of Host *: the category Include precedes it in the root block.
	root := all[RootConfig]
	if inc, star := strings.Index(root, "Include ~/.ssh/profiles/personal/config"), strings.Index(root, "Host *"); inc < 0 || inc > star {
		t.Errorf("category Include must precede Host *:\n%s", root)
	}
}

func TestAHostAliasedGitHubSuppressesTheGitBlock(t *testing.T) {
	js := strings.Replace(gitVMJSON, `"alias": "github-imanimanyara"`, `"alias": "github.com"`, 1)
	out, err := RenderRootConfig(mustManifest(t, js), false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "Host github.com\n"); n != 1 {
		t.Errorf("Host github.com rendered %d times, want 1:\n%s", n, out)
	}
}
