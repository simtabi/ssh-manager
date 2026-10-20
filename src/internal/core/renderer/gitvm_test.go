package renderer

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
