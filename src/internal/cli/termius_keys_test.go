package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKey is not a key. Its armor is assembled at run time so secret
// scanners do not mistake the test for a leaked key.
var fakeKey = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nthrowaway-test-key\n-----END OPENSSH " + "PRIVATE KEY-----\n"

// termiusKeysHome is exportHome with a throwaway private key written where
// oribi-web's key lives, so no test ever reads a real key.
func termiusKeysHome(t *testing.T) (keyPath string, clip *[]string) {
	t.Helper()
	exportHome(t)
	var got []string
	t.Cleanup(stubClipboard(func(s string) error { got = append(got, s); return nil }))
	out := run(t, "termius", "keys")
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "oribi-web" {
			keyPath = f[2]
		}
	}
	if keyPath == "" {
		t.Fatalf("oribi-web not listed:\n%s", out)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(fakeKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, &got
}

func TestTermiusKeysListsLabelsAndPaths(t *testing.T) {
	keyPath, clip := termiusKeysHome(t)
	out := run(t, "termius", "keys")
	label := filepath.Base(keyPath)
	if !strings.Contains(out, "TERMIUS LABEL") || !strings.Contains(out, label) || strings.HasSuffix(keyPath, ".pub") {
		t.Errorf("list should show label %s and the private key path:\n%s", label, out)
	}
	if strings.Contains(out, "github-me") {
		t.Errorf("git host listed without --include-git:\n%s", out)
	}
	if !strings.Contains(run(t, "termius", "keys", "--include-git"), "github-me") {
		t.Error("--include-git should list the git host")
	}
	if strings.Contains(out, "throwaway-test-key") || len(*clip) != 0 {
		t.Error("listing must neither print nor copy a key")
	}
}

func TestTermiusKeysCopiesWithoutPrinting(t *testing.T) {
	keyPath, clip := termiusKeysHome(t)
	out := run(t, "termius", "keys", "oribi-web")
	if len(*clip) != 1 || (*clip)[0] != fakeKey {
		t.Fatalf("the private key was not copied: %q", *clip)
	}
	if strings.Contains(out, "throwaway-test-key") || strings.Contains(out, "PRIVATE KEY-----") {
		t.Errorf("the key leaked to the output:\n%s", out)
	}
	if !strings.Contains(out, "label: "+filepath.Base(keyPath)) || !strings.Contains(out, "clipboard") {
		t.Errorf("should print the label and say it copied:\n%s", out)
	}
}

func TestTermiusKeysClearAfterAndClear(t *testing.T) {
	_, clip := termiusKeysHome(t)
	run(t, "termius", "keys", "oribi-web", "--clear-after", "1s")
	if len(*clip) != 2 || (*clip)[1] != "" {
		t.Errorf("--clear-after should copy then empty the clipboard: %q", *clip)
	}
	run(t, "termius", "keys", "--clear")
	if len(*clip) != 3 || (*clip)[2] != "" {
		t.Errorf("--clear should empty the clipboard: %q", *clip)
	}
}

func TestTermiusKeysPrintWarnsOnStderr(t *testing.T) {
	_, clip := termiusKeysHome(t)
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"termius", "keys", "oribi-web", "--print"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != fakeKey {
		t.Errorf("--print should put only the key on stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "warning") || len(*clip) != 0 {
		t.Errorf("--print should warn on stderr and not copy: %q %q", stderr.String(), *clip)
	}
}

func TestTermiusKeysRefusesUnknownAndNonKeys(t *testing.T) {
	keyPath, clip := termiusKeysHome(t)
	if _, err := runErr(t, "termius", "keys", "nope"); err == nil {
		t.Error("an unknown alias was accepted")
	}
	if _, err := runErr(t, "termius", "keys", "github-me"); err == nil {
		t.Error("a git host was copied without --include-git")
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runErr(t, "termius", "keys", "oribi-web"); err == nil || len(*clip) != 0 {
		t.Error("a file that is not a private key was copied")
	}
}
