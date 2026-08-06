package recover

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// fixkeys.sh is now shipped only as the embedded copy - there is no second file
// to drift from - so what is worth pinning is the script's own contract. It runs
// on a server the user is locked out of, edits authorized_keys, and is pasted
// into a provider's recovery console.
//
// Note it deliberately does NOT `set -e`: it is an interactive menu, and
// aborting the whole session because one command returned non-zero is the
// opposite of what a recovery tool should do.
func TestEmbeddedFixkeysKeepsItsContract(t *testing.T) {
	script := string(fixkeysScript)
	checks := []struct {
		want string
		why  string
	}{
		{"#!", "no shebang, so it depends on how it happens to be invoked"},
		{"set -u", "an unset variable in a script that rewrites authorized_keys must not expand to nothing"},
		{"/dev/tty", "prompts must read from the terminal, or pasting the script eats its own menu answers"},
		{"backup()", "it promises every change is backed up first"},
		{"write_atomic()", "a half-written authorized_keys is a lockout"},
	}
	for _, c := range checks {
		if !strings.Contains(script, c.want) {
			t.Errorf("fixkeys.sh is missing %q: %s", c.want, c.why)
		}
	}
	if strings.Contains(script, "rm -rf") {
		t.Error("a permissions repair script has no business deleting a tree")
	}
}

func TestScriptFullTool(t *testing.T) {
	got, err := Script(paths.Paths{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(fixkeysScript) {
		t.Error("no-key recover should return the fixkeys tool verbatim")
	}
}

func TestSnippet(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: base}
	mj := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git","key_name":"k"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	pubBody := "AAAAC3NzaC1lZDI1NTE5AAAAIKBhbiwvJigPhtwCSedPrebJ6NRC27KYLY3l/okYRnNA"
	pub := "ssh-ed25519 " + pubBody + " a comment\n"
	dir := filepath.Join(p.SSHDir, "profiles", "work")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "k.pub"), []byte(pub), 0o644)

	got, err := Script(p, &m, "k")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# key: k\n",
		"KEY='ssh-ed25519 " + pubBody + " a comment'\n", // comment kept, no trailing newline
		"BODY='" + pubBody + "'\n",
		"printf '%s\\n' \"$KEY\"", // literal backslash-n preserved for the runtime printf
	} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet missing %q\n---\n%s", want, got)
		}
	}

	// Unknown key -> error.
	if _, err := Script(p, &m, "nope"); err == nil {
		t.Error("unknown key should error")
	}
}

// writePub seeds a manifest + a public key on disk and returns the service inputs.
func writePub(t *testing.T, pub string) (paths.Paths, *manifest.Manifest) {
	t.Helper()
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: base}
	mj := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git","key_name":"k"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(p.SSHDir, "profiles", "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k.pub"), []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, &m
}

const pubBody = "AAAAC3NzaC1lZDI1NTE5AAAAIKBhbiwvJigPhtwCSedPrebJ6NRC27KYLY3l/okYRnNA"

// The snippet is pasted into a provider's recovery console as root, on a machine
// the user is locked out of. It has to actually run, and it has to survive a key
// comment containing a single quote - `ssh-keygen -C "Imani's laptop"` produces
// one, and a comment is free text that reaches a shell literal here. Broken
// quoting is either a script that fails when it is needed most or, with a
// hostile comment, arbitrary commands in a root console.
func TestTheSnippetRunsAndSurvivesQuotesInTheComment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the snippet is POSIX sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh")
	}
	// A comment that closes the literal, runs a command and reopens it - what a
	// naive concatenation would execute. The command it runs writes a file this
	// test owns, so a successful injection is visible rather than merely assumed
	// not to have happened.
	home := t.TempDir()
	canary := filepath.Join(home, "pwned")
	comment := "Imani's laptop'; touch " + canary + "; :'"
	p, m := writePub(t, "ssh-ed25519 "+pubBody+" "+comment+"\n")

	script, err := Script(p, m, "k")
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "recover.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		cmd := exec.Command(sh, scriptPath)
		cmd.Env = append(os.Environ(), "HOME="+home)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("the recovery snippet failed to run: %v\n%s\n--- script ---\n%s", err, out, script)
		}
	}
	run()

	ak := filepath.Join(home, ".ssh", "authorized_keys")
	got, err := os.ReadFile(ak)
	if err != nil {
		t.Fatalf("authorized_keys not written: %v", err)
	}
	want := "ssh-ed25519 " + pubBody + " " + comment
	if !strings.Contains(string(got), want) {
		t.Errorf("authorized_keys = %q\nwant the key verbatim, comment and all", got)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatal("the comment escaped its shell literal and executed")
	}

	// Re-running is the normal case - a locked-out user pastes it more than once -
	// and must not add the key twice.
	run()
	after, err := os.ReadFile(ak)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(after), pubBody); n != 1 {
		t.Errorf("the key appears %d times after two runs, want 1", n)
	}
	// It promises a backup before it edits.
	if _, err := os.Stat(ak + ".ssh-manager.bak"); err != nil {
		t.Errorf("no backup of authorized_keys was taken: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(ak)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("authorized_keys is %04o, want 0600 - sshd refuses a loose one", mode)
		}
	}
}

// A .pub that is not a public key must be refused rather than pasted into a
// root console as an authorized_keys line. The file is on disk and could be
// anything: a truncated write, a private key saved to the wrong name, a stray.
func TestAMalformedOrMissingPublicKeyIsRefused(t *testing.T) {
	p, m := writePub(t, "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n")
	if _, err := Script(p, m, "k"); err == nil {
		t.Error("a private key at the .pub path should be refused")
	}

	p2, m2 := writePub(t, "ssh-ed25519 "+pubBody+"\n")
	if err := os.Remove(filepath.Join(p2.SSHDir, "profiles", "work", "k.pub")); err != nil {
		t.Fatal(err)
	}
	_, err := Script(p2, m2, "k")
	if err == nil {
		t.Fatal("a missing public key should error")
	}
	// The error has to say what to do: this is the one command a user reaches for
	// when they are already locked out and have no second route in.
	if !strings.Contains(err.Error(), "reconcile") {
		t.Errorf("error = %q, want it to name the command that mints the key", err)
	}

	// No manifest at all is its own error, not a nil dereference.
	if _, err := Script(p2, nil, "k"); err == nil {
		t.Error("a key selector with no manifest should error")
	}
}
