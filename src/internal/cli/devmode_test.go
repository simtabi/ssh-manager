package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole point of dev mode is one property, so it gets tested as one
// property: run the verbs that write the most, and the real ~/.ssh must be
// untouched afterwards.
//
// editHome points HOME at a temp dir, so "the real ~/.ssh" here is that dir's -
// which is exactly the tree an unsandboxed run would write into, and the one a
// leak would show up in.
func TestDevModeWritesNothingOutsideItsRoot(t *testing.T) {
	real := editHome(t)
	realSSH := real.SSHDir
	if err := os.MkdirAll(realSSH, 0o700); err != nil {
		t.Fatal(err)
	}
	// A file that must survive byte for byte.
	canary := filepath.Join(realSSH, "config")
	const canaryText = "# hand-written, not managed by sshmgr\nHost example\n  User me\n"
	if err := os.WriteFile(canary, []byte(canaryText), 0o600); err != nil {
		t.Fatal(err)
	}

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	run(t, "--dev-root", sandbox, "init")
	// These may legitimately fail on a starter manifest; what matters is where
	// they wrote while trying.
	_, _ = runErr(t, "--dev-root", sandbox, "keygen", "--yes")
	_, _ = runErr(t, "--dev-root", sandbox, "config", "render", "--yes")

	got, err := os.ReadFile(canary)
	if err != nil {
		t.Fatalf("the real ~/.ssh/config is gone: %v", err)
	}
	if string(got) != canaryText {
		t.Errorf("dev mode rewrote the real ~/.ssh/config:\n%s", got)
	}
	// Nothing new either: a leak that creates rather than overwrites is still a
	// leak, and is the shape `init` and `keygen` would take.
	entries, err := os.ReadDir(realSSH)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dev mode created %v in the real ~/.ssh; it should have created nothing", names)
	}
	// ...and the sandbox did get the home it was told to build.
	if _, err := os.Stat(filepath.Join(sandbox, "config", "manifest.json")); err != nil {
		t.Errorf("the sandbox has no manifest, so the run may not have been sandboxed at all: %v", err)
	}
}

// A sandbox that overlaps the real tree in either direction is not a sandbox.
// Both directions are separately dangerous, so both are separately refused.
func TestASandboxMayNotOverlapTheRealTree(t *testing.T) {
	real := editHome(t)
	home := filepath.Dir(real.SSHDir)
	for _, tc := range []struct{ name, root, want string }{
		{"the real ssh dir itself", real.SSHDir, "is inside"},
		{"a directory under it", filepath.Join(real.SSHDir, "scratch"), "is inside"},
		{"the home directory, which contains it", home, "contains"},
		// Computed, not written as "/" or "\\": on Windows a bare separator is
		// not the root it resolves to, and hard-coding one meant this case
		// asserted nothing there. filesystemRoot walks up from the working
		// directory until Dir stops moving, which is the root on either system.
		{"the filesystem root", filesystemRoot(t), "filesystem root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runErr(t, "--dev-root", tc.root, "doctor")
			if err == nil {
				t.Fatalf("--dev-root %s was accepted", tc.root)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error was %q, want it to explain %q", err, tc.want)
			}
		})
	}
}

// The environment variable is the same switch as the flag - a test harness or a
// shell session sets it once rather than threading a flag through every call.
func TestTheEnvironmentVariableSandboxesToo(t *testing.T) {
	editHome(t)
	sandbox := filepath.Join(t.TempDir(), "sandbox")
	t.Setenv("SSHMGR_DEV_ROOT", sandbox)

	run(t, "init")
	if _, err := os.Stat(filepath.Join(sandbox, "config", "manifest.json")); err != nil {
		t.Errorf("$SSHMGR_DEV_ROOT did not redirect the run: %v", err)
	}
}

// The flag wins over the variable, so a shell that has been left in dev mode
// cannot silently redirect a run that names its own root.
func TestTheFlagBeatsTheEnvironmentVariable(t *testing.T) {
	editHome(t)
	fromEnv := filepath.Join(t.TempDir(), "from-env")
	fromFlag := filepath.Join(t.TempDir(), "from-flag")
	t.Setenv("SSHMGR_DEV_ROOT", fromEnv)

	run(t, "--dev-root", fromFlag, "init")
	if _, err := os.Stat(filepath.Join(fromFlag, "config", "manifest.json")); err != nil {
		t.Errorf("the flag was ignored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fromEnv, "config", "manifest.json")); err == nil {
		t.Error("the environment variable also took effect; one run wrote two homes")
	}
}

// Two actions reach outside any directory, so dev mode refuses them rather than
// letting a flag that promises "nothing real" do something real.
func TestTheActionsASandboxCannotContainAreRefused(t *testing.T) {
	editHome(t)
	sandbox := filepath.Join(t.TempDir(), "sandbox")
	run(t, "--dev-root", sandbox, "init")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"deploy uploads to a live account", []string{"deploy", "somekey"}},
		{"notify install registers a machine-wide job", []string{"notify", "install", "--yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runErr(t, append([]string{"--dev-root", sandbox}, tc.args...)...)
			if err == nil {
				t.Fatal("it ran")
			}
			if !strings.Contains(err.Error(), "refused in dev mode") {
				t.Errorf("error was %q, want it to say why it was refused", err)
			}
		})
	}
}

// Without the flag nothing changes: the default is the real tree, and dev mode
// must not be something you can end up in by accident.
func TestWithoutTheFlagTheRealTreeIsUsed(t *testing.T) {
	real := editHome(t)
	run(t, "init")
	if _, err := os.Stat(real.Manifest()); err != nil {
		t.Errorf("an unsandboxed run did not use the real config home: %v", err)
	}
}

// Every verb resolves paths through one function, so there is no verb that reads
// the sandbox and writes the real tree. A new verb that calls paths.Resolve
// directly would reintroduce exactly that, silently.
func TestNoVerbResolvesPathsBehindDevMode(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "devmode.go" {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "paths.Resolve(") {
			t.Errorf("%s calls paths.Resolve directly; use resolvePaths(c) so --dev-root applies to it too", name)
		}
	}
}

// filesystemRoot is the root of the volume the tests run on: "/" on Unix,
// "C:\\" (or whichever drive) on Windows.
func filesystemRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}
