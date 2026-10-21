package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exportHome is an edit home with one categorized profile, one plain one, and
// a git host, rendered, so ~/.ssh/config exists and Includes a category file.
func exportHome(t *testing.T) (dir string, before map[string]string) {
	t.Helper()
	p := editHome(t)
	run(t, "profile", "add", "simtabi", "--category", "orgs")
	run(t, "host", "add", "simtabi", "oribi-web", "-H", "143.198.186.131", "-u", "ploi")
	run(t, "profile", "add", "me")
	run(t, "host", "add", "me", "github-me", "-H", "github.com", "-u", "git")
	before = map[string]string{}
	for _, rel := range []string{"config", "profiles/orgs/config"} {
		b, err := os.ReadFile(filepath.Join(p.SSHDir, rel))
		if err != nil {
			t.Fatalf("%s was not rendered: %v", rel, err)
		}
		before[rel] = string(b)
	}
	return p.SSHDir, before
}

// assertUntouched is the promise both exports make: the split config is left
// exactly as it was.
func assertUntouched(t *testing.T, sshDir string, before map[string]string) {
	t.Helper()
	for rel, want := range before {
		got, err := os.ReadFile(filepath.Join(sshDir, rel))
		if err != nil || string(got) != want {
			t.Errorf("%s changed: an export must never touch the rendered config", rel)
		}
	}
}

func TestConfigExportFlatWritesOneFileAndLeavesTheSplitConfigAlone(t *testing.T) {
	sshDir, before := exportHome(t)
	out := run(t, "config", "export", "--flat")
	path := filepath.Join(os.Getenv("SSH_MANAGER_HOME"), "exports", "ssh_config")
	if !strings.Contains(out, path) {
		t.Errorf("the command should say where it wrote:\n%s", out)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "Host oribi-web\n") || strings.Contains(text, "Include ") {
		t.Errorf("not a flat export:\n%s", text)
	}
	if !strings.Contains(text, "IdentityFile "+sshDir+"/profiles/orgs/simtabi/") {
		t.Errorf("key paths are not absolute:\n%s", text)
	}
	assertMode(t, path, 0o600, "the export lists every host and key path")
	assertUntouched(t, sshDir, before)
}

func TestConfigExportFlatToStdout(t *testing.T) {
	sshDir, before := exportHome(t)
	out := run(t, "config", "export", "--flat", "--out", "-")
	if !strings.Contains(out, "Host oribi-web\n") {
		t.Errorf("--out - should print the export:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("SSH_MANAGER_HOME"), "exports")); err == nil {
		t.Error("--out - must not write a file")
	}
	assertUntouched(t, sshDir, before)
}

// The guard that keeps the feature opt-in: no path the export accepts may be a
// file `config render` owns, however it is spelled.
func TestConfigExportRefusesTheRenderedConfigFiles(t *testing.T) {
	sshDir, before := exportHome(t)
	for _, target := range []string{
		filepath.Join(sshDir, "config"),
		filepath.Join(sshDir, "profiles", "orgs", "config"),
		filepath.Join(sshDir, "profiles", "orgs", "..", "..", "config"),
	} {
		if _, err := runErr(t, "config", "export", "--flat", "--out", target); err == nil {
			t.Errorf("export over %s was accepted", target)
		}
	}
	if _, err := runErr(t, "termius", "export", "--out", filepath.Join(sshDir, "config")); err == nil {
		t.Error("termius export over ~/.ssh/config was accepted")
	}
	// Anything inside ~/.ssh is refused, not only the rendered files: the trust
	// store and keys live there too. Spelled with other case it is the same
	// directory on a case-insensitive filesystem (APFS, NTFS), and a symlinked
	// directory is the same directory too.
	link := filepath.Join(t.TempDir(), "sshlink")
	if err := os.Symlink(sshDir, link); err != nil {
		t.Fatal(err)
	}
	targets := []string{
		filepath.Join(sshDir, "known_hosts"),
		filepath.Join(sshDir, "profiles", "orgs", "new-file"),
		filepath.Join(link, "config"),
	}
	if caseInsensitiveFS(t, sshDir) {
		targets = append(targets,
			filepath.Join(sshDir, "Config"),
			filepath.Join(filepath.Dir(sshDir), ".SSH", "config"))
	}
	for _, target := range targets {
		if _, err := runErr(t, "config", "export", "--flat", "--out", target); err == nil {
			t.Errorf("export into ~/.ssh via %s was accepted", target)
		}
	}
	assertUntouched(t, sshDir, before)
}

func TestConfigExportNeedsAFormat(t *testing.T) {
	exportHome(t)
	if _, err := runErr(t, "config", "export"); err == nil || !strings.Contains(err.Error(), "--flat") {
		t.Errorf("export without a format should name the one it supports: %v", err)
	}
}

func TestTermiusExportWritesTheCSVAndListsKeys(t *testing.T) {
	sshDir, before := exportHome(t)
	out := run(t, "termius", "export")
	path := filepath.Join(os.Getenv("SSH_MANAGER_HOME"), "exports", "termius-hosts.csv")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.HasPrefix(string(b), "Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password\n") {
		t.Errorf("not the Termius template header:\n%s", b)
	}
	if !strings.Contains(string(b), "simtabi,oribi-web,,143.198.186.131,ssh,22,ploi,\n") {
		t.Errorf("oribi-web row missing:\n%s", b)
	}
	if strings.Contains(string(b), "github-me") {
		t.Errorf("a git host was exported without --include-git:\n%s", b)
	}
	for _, want := range []string{"oribi-web", sshDir + "/profiles/orgs/simtabi/", "github-me", "Import"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should mention %q:\n%s", want, out)
		}
	}
	assertMode(t, path, 0o600, "the export lists every host")
	assertUntouched(t, sshDir, before)

	if out := run(t, "termius", "export", "--include-git", "--out", "-"); !strings.Contains(out, "github-me") {
		t.Errorf("--include-git should export the git host:\n%s", out)
	}
}

// --open hands the file to Termius on macOS and refuses elsewhere; the opener
// is swapped so the test never launches an app.
func TestTermiusExportOpen(t *testing.T) {
	exportHome(t)
	var calls [][]string
	restore := stubOpener(func(args ...string) error {
		calls = append(calls, args)
		return nil
	})
	defer restore()

	if !onMacOS() {
		if _, err := runErr(t, "termius", "export", "--open"); err == nil {
			t.Error("--open off macOS should be refused")
		}
		return
	}
	run(t, "termius", "export", "--open")
	if len(calls) != 2 || strings.Join(calls[0], " ") != "-a Termius" || calls[1][0] != "-R" {
		t.Errorf("opener calls = %v", calls)
	}

	restore2 := stubOpener(func(...string) error { return errors.New("no Termius") })
	defer restore2()
	if _, err := runErr(t, "termius", "export", "--open"); err == nil {
		t.Error("a failed open should be reported")
	}
}

// Under --out - the CSV owns stdout and the report goes to stderr, so
// `sshmgr termius export --out - > hosts.csv` yields a clean file.
func TestTermiusExportToStdoutKeepsTheReportOnStderr(t *testing.T) {
	exportHome(t)
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"termius", "export", "--out", "-", "--skip", "github-me"})
	if err := root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "Groups,") || strings.Contains(stdout.String(), "skipped") {
		t.Errorf("stdout should be the CSV alone:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "oribi-web") || !strings.Contains(stderr.String(), "github-me: --skip") {
		t.Errorf("stderr should carry the report:\n%s", stderr.String())
	}
}

// caseInsensitiveFS reports whether dir's filesystem folds case, so the
// spelled-differently cases run only where they mean the same file.
func caseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(filepath.Dir(dir), strings.ToUpper(filepath.Base(dir))))
	return err == nil
}
