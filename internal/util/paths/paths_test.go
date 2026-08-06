package paths

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func env(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestConfigDirDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		want := filepath.Join(`C:\AppData`, "ssh-manager")
		if got := ConfigDir(env(map[string]string{"APPDATA": `C:\AppData`}), ""); got != want {
			t.Fatalf("windows default = %q, want %q", got, want)
		}
		return
	}
	// Unix/macOS: XDG_CONFIG_HOME or ~/.config, + ssh-manager.
	if got := ConfigDir(env(map[string]string{"HOME": "/tmp/h"}), "/cwd"); got != "/tmp/h/.config/ssh-manager" {
		t.Fatalf("default = %q, want /tmp/h/.config/ssh-manager", got)
	}
	if got := ConfigDir(env(map[string]string{"HOME": "/tmp/h", "XDG_CONFIG_HOME": "/tmp/xdg"}), "/cwd"); got != "/tmp/xdg/ssh-manager" {
		t.Fatalf("XDG = %q, want /tmp/xdg/ssh-manager", got)
	}
}

// absPath builds an OS-absolute path (drive-letter rooted on Windows).
func absPath(parts ...string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(append([]string{`C:\`}, parts...)...)
	}
	return filepath.Join(append([]string{"/"}, parts...)...)
}

func TestConfigDirOverride(t *testing.T) {
	abs := absPath("abs", "home")
	cwd := absPath("cwd")
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"SSH_MANAGER_HOME": abs}, abs},
		{map[string]string{"SSH_MANAGER_CONFIG_DIR": abs}, abs},                   // alias
		{map[string]string{"SSH_MANAGER_HOME": "rel"}, filepath.Join(cwd, "rel")}, // relative absolutized
	}
	for _, c := range cases {
		if got := ConfigDir(env(c.env), cwd); got != c.want {
			t.Errorf("ConfigDir(%v) = %q, want %q", c.env, got, c.want)
		}
	}
	// An empty override falls through to the OS default (not treated as set).
	got := ConfigDir(env(map[string]string{"SSH_MANAGER_HOME": "", "HOME": "/tmp/h", "APPDATA": `C:\A`}), cwd)
	if filepath.Base(got) != "ssh-manager" {
		t.Errorf("empty override should fall through to default, got %q", got)
	}
}

func TestPathsLayout(t *testing.T) {
	h := absPath("home", "x")
	ssh := absPath("ssh")
	p := Resolve(env(map[string]string{"SSH_MANAGER_HOME": h}), absPath("cwd"), ssh)
	checks := map[string]string{
		"home":        p.Home(),
		"manifest":    p.Manifest(),
		"env":         p.EnvFile(),
		"auditLog":    p.AuditLog(),
		"lockFile":    p.LockFile(),
		"distDir":     p.DistDir(),
		"expiryCache": p.ExpiryCache(),
	}
	want := map[string]string{
		"home":        h,
		"manifest":    filepath.Join(h, "manifest.json"),
		"env":         filepath.Join(h, ".env"),
		"auditLog":    filepath.Join(h, "log", "audit.log"),
		"lockFile":    filepath.Join(h, ".state", ".lock"),
		"distDir":     filepath.Join(h, "dist"),
		"expiryCache": filepath.Join(h, ".state", "expiry-cache.json"),
	}
	for k := range want {
		if checks[k] != want[k] {
			t.Errorf("%s = %q, want %q", k, checks[k], want[k])
		}
	}
	if p.SSHDir != ssh {
		t.Errorf("SSHDir = %q, want %q", p.SSHDir, ssh)
	}
}

// isolateHome points the real home lookup at a clean directory, so ~/.sshmgr on
// the machine running the tests cannot make FirstLegacyHome return something the
// test did not create.
func isolateHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// FirstLegacyHome decides what `migrate` moves - it renames the directory it
// names, and with --force replaces the current home with it. Each exclusion
// exists to stop that happening to something it should not: a regular file left
// at the legacy path, a symlink whose target lives anywhere at all, and the
// standard home itself when the two paths coincide.
func TestFirstLegacyHomeSkipsWhatItMustNotMigrate(t *testing.T) {
	isolateHome(t)
	base := t.TempDir()
	p := Paths{ConfigDir: filepath.Join(base, "ssh-manager")}
	sibling := filepath.Join(base, "sshmgr")

	if got := p.FirstLegacyHome(); got != "" {
		t.Errorf("nothing exists yet, got %q", got)
	}

	// A regular file at the legacy path is not a home to migrate.
	if err := os.WriteFile(sibling, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := p.FirstLegacyHome(); got != "" {
		t.Errorf("a regular file was offered for migration: %q", got)
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}

	// A symlink is refused whatever it points at: migrate renames what it is
	// given, which for a link means moving the link and leaving the real
	// directory stranded, or - with --force - replacing the home with one.
	if runtime.GOOS != "windows" {
		target := filepath.Join(base, "elsewhere")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, sibling); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if got := p.FirstLegacyHome(); got != "" {
			t.Errorf("a symlinked legacy home was offered for migration: %q", got)
		}
		if err := os.Remove(sibling); err != nil {
			t.Fatal(err)
		}
	}

	// A real directory is what it is looking for.
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := p.FirstLegacyHome(); got != sibling {
		t.Errorf("FirstLegacyHome = %q, want %q", got, sibling)
	}

	// When the standard home *is* the sibling, there is nothing to migrate - and
	// migrating a directory onto itself would destroy it.
	self := Paths{ConfigDir: sibling}
	if got := self.FirstLegacyHome(); got == sibling {
		t.Error("the standard home was offered as its own legacy home")
	}
}

// A home override is something a user types, and both `~/sshmgr-home` and
// `~\sshmgr-home` are things they type. Honouring only the forward-slash form
// leaves a literal tilde in the path, so every file lands in a directory called
// "~" beside wherever the process happened to be started.
func TestATildeOverrideExpandsWithEitherSeparator(t *testing.T) {
	h := absPath("users", "me")
	e := env(map[string]string{"HOME": h, "USERPROFILE": h})
	cwd := absPath("cwd")

	for _, in := range []string{"~/sshmgr-home", `~\sshmgr-home`} {
		want := filepath.Join(h, "sshmgr-home")
		got := ConfigDir(env(map[string]string{
			"HOME": h, "USERPROFILE": h, "SSH_MANAGER_HOME": in,
		}), cwd)
		if got != want {
			t.Errorf("ConfigDir(%q) = %q, want %q", in, got, want)
		}
	}
	// A bare "~" is the home itself, not a directory named "~" inside it.
	if got := expandUser("~", e); got != h {
		t.Errorf(`expandUser("~") = %q, want %q`, got, h)
	}
	// Another user's home is not ours to expand.
	const other = "~someone/else"
	if got := expandUser(other, e); got != other {
		t.Errorf("expandUser(%q) = %q, want it left alone", other, got)
	}
}

// Resolve's default SSHDir is ~/.ssh, taken from the injected environment rather
// than the process's, so every command in one invocation agrees on which tree it
// is managing.
func TestResolveDefaultsSSHDirToTheHomeItWasGiven(t *testing.T) {
	h := absPath("users", "me")
	p := Resolve(env(map[string]string{
		"HOME": h, "USERPROFILE": h, "SSH_MANAGER_HOME": absPath("cfg"),
	}), absPath("cwd"), "")
	if want := filepath.Join(h, ".ssh"); p.SSHDir != want {
		t.Errorf("SSHDir = %q, want %q", p.SSHDir, want)
	}
}

// X1 - the public environment variables, as one table.
//
// These are the tool's configuration API: a user sets them in a shell profile or
// a CI job, and a rename is a silent break for everyone who did. There are
// seven, and the pair at the top are aliases for the same thing.
func TestThePublicEnvironmentVariablesResolveAsDocumented(t *testing.T) {
	abs := absPath("elsewhere")
	cwd := absPath("cwd")

	// SSH_MANAGER_HOME and its alias both override, and HOME wins over the alias
	// when both are set - it is the documented primary.
	if got := ConfigDir(env(map[string]string{"SSH_MANAGER_HOME": abs}), cwd); got != abs {
		t.Errorf("SSH_MANAGER_HOME = %q, want %q", got, abs)
	}
	if got := ConfigDir(env(map[string]string{"SSH_MANAGER_CONFIG_DIR": abs}), cwd); got != abs {
		t.Errorf("SSH_MANAGER_CONFIG_DIR = %q, want %q", got, abs)
	}
	other := absPath("second")
	if got := ConfigDir(env(map[string]string{
		"SSH_MANAGER_HOME": abs, "SSH_MANAGER_CONFIG_DIR": other,
	}), cwd); got != abs {
		t.Errorf("with both set the result was %q; SSH_MANAGER_HOME is the primary", got)
	}
}

// The names themselves, asserted against the source that reads them. A variable
// renamed in code and not here - or here and not in code - is a break for every
// user who set it, and nothing else in the suite would notice.
func TestTheEnvironmentVariableNamesAreTheDocumentedOnes(t *testing.T) {
	documented := map[string]string{
		"SSH_MANAGER_HOME":                 "the config home; absolutised against cwd if relative",
		"SSH_MANAGER_CONFIG_DIR":           "alias for SSH_MANAGER_HOME",
		"SSH_MANAGER_AUTO_PIN":             "0 disables auto-pinning reachable hosts on reconcile",
		"SSH_MANAGER_AGE_RECIPIENT":        "default age recipient for bundle",
		"SSH_MANAGER_AGE_IDENTITY_FILE":    "default age identity for restore",
		"SSH_MANAGER_SNAPSHOT_RETAIN":      "how many ~/.ssh snapshots to keep",
		"SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS": "when an archived predecessor is called stale",
	}
	found := readEnvNamesFromSource(t)
	for name := range documented {
		if !found[name] {
			t.Errorf("%s is documented here but nothing in the source reads it", name)
		}
	}
	for name := range found {
		if _, ok := documented[name]; !ok {
			t.Errorf("%s is read by the source but not documented here; "+
				"it is part of the tool's configuration API either way", name)
		}
	}
}

// readEnvNamesFromSource collects every SSH_MANAGER_* literal in the non-test
// tree, so the table above is checked against the code rather than against
// itself.
func readEnvNamesFromSource(t *testing.T) map[string]bool {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`SSH_MANAGER_[A-Z_]+`)
	found := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for _, m := range re.FindAllString(string(b), -1) {
				found[m] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}
