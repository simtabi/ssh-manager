package secrets

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestResolvePlainAndEmpty(t *testing.T) {
	if got := Resolve("ghp_token123"); got != "ghp_token123" {
		t.Errorf("plain value should pass through, got %q", got)
	}
	if got := Resolve(""); got != "" {
		t.Errorf("empty -> empty, got %q", got)
	}
}

func TestResolveCmd(t *testing.T) {
	// echo is portable enough for the test; trimmed stdout is the secret.
	if got := Resolve("cmd:echo  hunter2 "); got != "hunter2" {
		t.Errorf("cmd: secret = %q want hunter2", got)
	}
	// A failing command -> "" (degrade to manual).
	if got := Resolve("cmd:false"); got != "" {
		t.Errorf("failing cmd -> empty, got %q", got)
	}
}

func TestShlexSplit(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`op read op://Private/GitHub/token`, []string{"op", "read", "op://Private/GitHub/token"}},
		{`sh -c 'echo hi there'`, []string{"sh", "-c", "echo hi there"}},
		{`a "b c" d`, []string{"a", "b c", "d"}},
		{``, nil},
	}
	for _, c := range cases {
		if got := shlexSplit(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("shlexSplit(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

// stubCommand puts an executable first on PATH and returns the file it logs its
// arguments to, so what actually reached exec can be inspected.
func stubCommand(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "argv.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$#\" >> " + log + "\nfor a in \"$@\"; do printf '[%s]\\n' \"$a\" >> " + log + "; done\n" + body
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// The cmd: value comes out of providers.json, which is a config file - editable
// by anything running as the user, and syncable between machines. It is split
// into an argv and exec'd directly, never handed to a shell, so the shell
// metacharacters in it stay inert. Routing this through `sh -c` would turn a
// config file into arbitrary command execution.
func TestACmdSecretIsExecutedAsArgvNotThroughAShell(t *testing.T) {
	log := stubCommand(t, "pass", "printf 'the-token\\n'\n")
	canary := filepath.Join(t.TempDir(), "shell-ran")

	got := Resolve("cmd:pass show token; touch " + canary)
	if got != "the-token" {
		t.Errorf("secret = %q, want the stub's output", got)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatal("the value was interpreted by a shell; a config file can now run commands")
	}
	// The semicolon and everything after it arrived as ordinary arguments.
	argv, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[show]", "[token;]", "[touch]"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("argv = %q, want %s passed through as an argument", argv, want)
		}
	}
}

// A cmd: secret that fails resolves to empty, and the raw "cmd:..." string must
// never leak out in its place - it would be sent to the provider as the bearer
// token, and a rejected request looks nothing like "your password manager is
// locked".
func TestAFailedLookupYieldsNothingRatherThanTheRawValue(t *testing.T) {
	const raw = "cmd:definitely-not-a-real-command-9d3f"
	got := Resolve(raw)
	if got == raw {
		t.Fatal("the unresolved cmd: value was returned as the secret")
	}
	if got != "" {
		t.Errorf("failed lookup = %q, want empty", got)
	}
}

// Failures are not memoized. A cmd: secret usually fails because the store is
// locked; caching that would mean the user unlocks it, retries, and keeps
// getting the same empty token for the life of the process - permanent in the
// TUI, which is long-lived. Successes are memoized, since re-running the command
// means re-prompting.
func TestOnlySuccessfulLookupsAreMemoized(t *testing.T) {
	dir := t.TempDir()
	flag := filepath.Join(dir, "unlocked")
	counter := filepath.Join(dir, "runs")
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf 'x' >> " + counter + "\n" +
		"[ -f " + flag + " ] || exit 1\nprintf 'the-token\\n'\n"
	if runtime.GOOS == "windows" {
		t.Skip("the stub is a shell script")
	}
	if err := os.WriteFile(filepath.Join(bin, "vault-stub"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	const raw = "cmd:vault-stub"

	if got := Resolve(raw); got != "" {
		t.Fatalf("locked store should resolve to empty, got %q", got)
	}
	// The user unlocks it and tries again.
	if err := os.WriteFile(flag, []byte("y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Resolve(raw); got != "the-token" {
		t.Fatalf("after unlocking, the retry got %q - the failure was cached", got)
	}
	// And now it is cached: a third call must not run the command again.
	runsBefore := runCount(t, counter)
	if got := Resolve(raw); got != "the-token" {
		t.Fatalf("memoized lookup = %q", got)
	}
	if runCount(t, counter) != runsBefore {
		t.Error("a successful lookup was re-run; every provider call would re-prompt")
	}
}

func runCount(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return len(b)
}
