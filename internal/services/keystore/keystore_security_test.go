package keystore

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/askpass"
)

// TestMain mirrors cmd/sshmgr: when ssh-keygen executes this binary as its
// askpass helper it must answer with the passphrase instead of running tests.
func TestMain(m *testing.M) {
	if askpass.Serving() {
		os.Exit(askpass.Serve(os.Stdout))
	}
	os.Exit(m.Run())
}

const testPassphrase = "correct-horse-battery-staple"

// fakeKeygen puts a recording stand-in for ssh-keygen at the front of PATH and
// returns the path of the file capturing each invocation's arguments.
func fakeKeygen(t *testing.T, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in for ssh-keygen is POSIX-only")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "argv")
	script := `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a" >> "$SSHMGR_TEST_ARGV"; done
for a in "$@"; do
  if [ "$a" = "-lf" ]; then
    echo "256 SHA256:ZmFrZWZpbmdlcnByaW50Zm9ydGVzdGluZ29ubHk test (ED25519)"
    exit 0
  fi
done
prev=""; out=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then out="$a"; fi
  prev="$a"
done
if [ -n "$out" ] && [ "$SSHMGR_TEST_EXIT" = "0" ]; then
  printf 'PRIVATE KEY-----\n' > "$out"
  printf 'ssh-ed25519 AAAAfake test\n' > "$out.pub"
fi
exit "$SSHMGR_TEST_EXIT"
`
	bin := filepath.Join(dir, "ssh-keygen")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHMGR_TEST_ARGV", record)
	t.Setenv("SSHMGR_TEST_EXIT", map[bool]string{true: "0", false: "1"}[exitCode == 0])
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return record
}

// A passphrase on the command line is readable by every local user through ps
// and /proc/<pid>/cmdline for as long as ssh-keygen runs, so it must never be
// passed as an argument.
func TestPassphraseNeverReachesArgv(t *testing.T) {
	record := fakeKeygen(t, 0)
	dir := t.TempDir()

	if _, err := New().Generate(filepath.Join(dir, "id_ed25519"),
		"ed25519", "test", testPassphrase, false); err != nil {
		t.Fatalf("generate: %v", err)
	}

	argv, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("ssh-keygen was never invoked: %v", err)
	}
	for i, arg := range strings.Split(strings.TrimSpace(string(argv)), "\n") {
		if strings.Contains(arg, testPassphrase) {
			t.Fatalf("passphrase leaked into ssh-keygen argv at position %d: %q", i, arg)
		}
	}
	if strings.Contains(string(argv), "-N") {
		t.Error("-N must not be used for a non-empty passphrase")
	}
}

// The passphrase still has to arrive, or the fix would be a silent downgrade to
// unencrypted keys.
func TestPassphraseEncryptsTheKey(t *testing.T) {
	requireTool(t)
	dir := t.TempDir()
	priv := filepath.Join(dir, "id_ed25519")

	if _, err := New().Generate(priv, "ed25519", "test", testPassphrase, false); err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", priv).Run(); err == nil {
		t.Fatal("key opened with an empty passphrase: it was never encrypted")
	}
	if err := exec.Command("ssh-keygen", "-y", "-P", testPassphrase, "-f", priv).Run(); err != nil {
		t.Fatalf("key does not open with the requested passphrase: %v", err)
	}
}

// Writing through a symlink would put private key material wherever the link
// points, chosen by whoever was able to create it.
func TestGenerateRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	priv := filepath.Join(dir, "id_ed25519")
	if err := os.Symlink(elsewhere, priv); err != nil {
		t.Fatal(err)
	}

	_, err := New().Generate(priv, "ed25519", "test", "", false)
	if err == nil {
		t.Fatal("generating onto a symlink should fail")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should name the symlink, got: %v", err)
	}
	if _, statErr := os.Stat(elsewhere); statErr == nil {
		t.Error("key material was written through the symlink")
	}
}

// A failed mint must not strand key material in the staging directory.
func TestGenerateCleansStagingOnFailure(t *testing.T) {
	fakeKeygen(t, 1)
	dir := t.TempDir()

	if _, err := New().Generate(filepath.Join(dir, "id_ed25519"),
		"ed25519", "test", "", false); err == nil {
		t.Fatal("generate should fail when ssh-keygen does")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".mint-*"))
	if len(leftovers) > 0 {
		t.Errorf("staging directories left behind: %v", leftovers)
	}
}

// A successful mint must not leave the staging directory either.
func TestGenerateCleansStagingOnSuccess(t *testing.T) {
	requireTool(t)
	dir := t.TempDir()

	if _, err := New().Generate(filepath.Join(dir, "id_ed25519"),
		"ed25519", "test", "", false); err != nil {
		t.Fatal(err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".mint-*"))
	if len(leftovers) > 0 {
		t.Errorf("staging directories left behind: %v", leftovers)
	}
}
