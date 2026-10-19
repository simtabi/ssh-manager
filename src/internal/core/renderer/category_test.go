package renderer

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const categorizedJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "personal": {"category": "internal", "hosts": [
      {"alias": "github-imani", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "legacy": {"hosts": [
      {"alias": "box", "hostname": "box.example", "user": "me", "key_name": "legacy-ed25519"}]},
    "adelsaiq": {"category": "clients", "hosts": [
      {"alias": "github-danniela", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]}
  }
}`

func TestCategoriesRenderIntoTheirOwnIncludedFiles(t *testing.T) {
	m := mustManifest(t, categorizedJSON)
	out, err := RenderAll(m, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config", "profiles/clients/config", "profiles/internal/config"}
	got := keys(out)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rendered %v, want %v", got, want)
	}

	root := out[RootConfig]
	includes := "Match all\n" +
		"Include ~/.ssh/profiles/internal/config\n" +
		"Include ~/.ssh/profiles/clients/config\n"
	if !strings.HasPrefix(root, ManagedHeader+"\n\n"+includes) {
		t.Errorf("root config must open with the category Includes, in manifest order:\n%s", root)
	}
	if strings.Contains(root, "github-imani") || strings.Contains(root, "github-danniela") {
		t.Errorf("a categorized host rendered inline in the root config:\n%s", root)
	}
	if !strings.Contains(root, "Host box\n") {
		t.Errorf("the uncategorized profile must stay inline:\n%s", root)
	}
	if i, j := strings.Index(root, "Include "), strings.Index(root, "Host *"); i < 0 || j < i {
		t.Errorf("Includes must precede Host *, or its values win over theirs:\n%s", root)
	}

	internal := out["profiles/internal/config"]
	if !IsManagedFile(internal) {
		t.Errorf("a category file must carry the managed header:\n%s", internal)
	}
	if !strings.Contains(internal, "IdentityFile ~/.ssh/profiles/internal/personal/imani_github-ed25519\n") {
		t.Errorf("category file has the wrong IdentityFile:\n%s", internal)
	}
	if strings.Contains(internal, "Host *") || strings.Contains(internal, "adelsaiq") {
		t.Errorf("a category file holds only its own profiles and no Host *:\n%s", internal)
	}
}

func TestNoCategoriesRendersNoMatchAll(t *testing.T) {
	m := mustManifest(t, `{"version":1,"profiles":{"p":{"hosts":[
		{"alias":"a","hostname":"a.example","user":"u"}]}}}`)
	out, err := RenderAll(m, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || strings.Contains(out[RootConfig], "Match all") || strings.Contains(out[RootConfig], "Include") {
		t.Errorf("a manifest without categories must render as before:\n%s", out[RootConfig])
	}
}

// The reason the Includes open with `Match all`, pinned against OpenSSH itself
// rather than a comment: foreign content above the managed block that ends
// inside a Host block scopes a bare Include to that host. Both halves run, so
// the test notices if ssh ever stops behaving this way and the line becomes
// dead weight - or if the renderer drops it.
func TestMatchAllKeepsIncludesGlobalUnderAForeignHostBlock(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh client")
	}
	m := mustManifest(t, categorizedJSON)
	out, err := RenderAll(m, false)
	if err != nil {
		t.Fatal(err)
	}
	identity := func(t *testing.T, root string) string {
		t.Helper()
		dir := t.TempDir()
		for rel, content := range out {
			if rel == RootConfig {
				continue
			}
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Point the Includes at the temp tree instead of the real ~/.ssh.
		root = strings.ReplaceAll(root, "Include ~/.ssh/", "Include "+dir+"/")
		cfg := filepath.Join(dir, "config")
		if err := os.WriteFile(cfg, []byte(root), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := exec.Command("ssh", "-G", "-F", cfg, "github-danniela").CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G: %v\n%s", err, b)
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if f := strings.Fields(ln); len(f) == 2 && f[0] == "identityfile" {
				return f[1]
			}
		}
		return ""
	}
	foreign := "Host somewhere-else\n    User nobody\n\n"
	composed := ComposeRootConfig(foreign, out[RootConfig])

	if got := identity(t, composed); !strings.HasSuffix(got, "/profiles/clients/adelsaiq/imani_github-ed25519") {
		t.Errorf("with Match all, the client alias should resolve its key; ssh -G gave %q", got)
	}
	bare := strings.Replace(composed, "Match all\n", "", 1)
	if got := identity(t, bare); strings.Contains(got, "adelsaiq") {
		t.Errorf("without Match all the Include should be scoped to the foreign Host; "+
			"ssh resolved %q, so the line may no longer be needed", got)
	}
}

func TestIsManagedFileRecognisesBothHeaders(t *testing.T) {
	for content, want := range map[string]bool{
		ManagedHeader + "\nHost a\n": true,
		legacyHeaders[0] + "\n":      true,
		"Host a\n":                   false,
		"":                           false,
	} {
		if got := IsManagedFile(content); got != want {
			t.Errorf("IsManagedFile(%q) = %v, want %v", content, got, want)
		}
	}
}
