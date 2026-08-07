package askpass

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// This package has no v1 counterpart to be in parity with - it exists
// because of what v1 did. v1's keystore
// (47-56) passed the passphrase to ssh-keygen as `-N <passphrase>`,
// and argv is world-readable through ps and /proc/<pid>/cmdline for as long as
// the process runs. Recorded as deviation D9 in MIGRATION_PLAN.md.
//
// So what is asserted here is the property that replaced it: the passphrase
// travels in the environment, which only the owning user and root can read.

func TestServingGatesOnTheExactMarker(t *testing.T) {
	for value, want := range map[string]bool{
		"1": true, "": false, "0": false, "true": false, "11": false, " 1": false,
	} {
		t.Setenv(modeVar, value)
		if got := Serving(); got != want {
			t.Errorf("%s=%q -> Serving()=%v, want %v", modeVar, value, got, want)
		}
	}
	// Unset is not serving: an ordinary invocation must parse its command line.
	if err := os.Unsetenv(modeVar); err != nil {
		t.Fatal(err)
	}
	if Serving() {
		t.Error("an ordinary invocation should not be in askpass mode")
	}
}

// ssh-keygen reads one line from the helper's stdout.
func TestServeWritesTheSecretAndOneNewline(t *testing.T) {
	t.Setenv(secretVar, "correct horse battery staple")
	var out bytes.Buffer
	if code := Serve(&out); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if got := out.String(); got != "correct horse battery staple\n" {
		t.Errorf("wrote %q", got)
	}

	// An empty passphrase is a legitimate answer, not an error: it is how an
	// unencrypted key is minted.
	t.Setenv(secretVar, "")
	out.Reset()
	if code := Serve(&out); code != 0 || out.String() != "\n" {
		t.Errorf("empty secret: code=%d wrote %q", code, out.String())
	}
}

func TestEnvironCarriesTheHandshake(t *testing.T) {
	env := Environ("/usr/local/bin/sshmgr", "s3cret")
	got := asMap(t, env)

	for name, want := range map[string]string{
		"SSH_ASKPASS":         "/usr/local/bin/sshmgr",
		"SSH_ASKPASS_REQUIRE": "force",
		modeVar:               "1",
		secretVar:             "s3cret",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
	// The parent's own environment is otherwise carried through: ssh-keygen
	// needs PATH and HOME to work at all.
	if os.Getenv("PATH") != "" && got["PATH"] == "" {
		t.Error("PATH did not survive into the child environment")
	}
}

// The one that matters. getenv returns the first match, so an inherited value
// left in place would win over the appended override - and an inherited
// SSHMGR_ASKPASS_SECRET is attacker-controlled input deciding what passphrase
// protects a freshly minted key.
func TestEnvironDropsInheritedValuesRatherThanShadowingThem(t *testing.T) {
	t.Setenv(secretVar, "attacker-supplied")
	t.Setenv(modeVar, "1")
	t.Setenv("SSH_ASKPASS", "/tmp/evil")
	t.Setenv("SSH_ASKPASS_REQUIRE", "never")

	env := Environ("/usr/local/bin/sshmgr", "the-real-secret")

	counts := map[string]int{}
	for _, kv := range env {
		if name, _, ok := strings.Cut(kv, "="); ok {
			counts[name]++
		}
	}
	for _, name := range []string{secretVar, modeVar, "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"} {
		if counts[name] != 1 {
			t.Errorf("%s appears %d times; a duplicate lets the inherited value win", name, counts[name])
		}
	}
	got := asMap(t, env)
	if got[secretVar] != "the-real-secret" {
		t.Errorf("secret = %q, want the one we passed, not the inherited value", got[secretVar])
	}
	if got["SSH_ASKPASS"] != "/usr/local/bin/sshmgr" {
		t.Errorf("SSH_ASKPASS = %q; an inherited helper path must not survive", got["SSH_ASKPASS"])
	}
}

// The passphrase must never reach a command line. Environ is the only channel;
// this asserts the secret is in the environment and that nothing about the
// helper handshake asks for it as an argument.
func TestSecretTravelsOnlyInTheEnvironment(t *testing.T) {
	// A marker, not a plausible secret: the test only needs a value it can find
	// again in the environment, and a high-entropy literal next to the word
	// "secret" is what a secret scanner is built to flag.
	const secret = "THE-TEST-VALUE"
	env := Environ("/usr/local/bin/sshmgr", secret)

	found := false
	for _, kv := range env {
		if kv == secretVar+"="+secret {
			found = true
		}
	}
	if !found {
		t.Fatal("the secret is not in the child environment, so ssh-keygen cannot read it")
	}
	// Serving() takes no argument, and Serve reads the environment - the helper
	// never receives the passphrase on its command line either.
	for _, arg := range os.Args {
		if strings.Contains(arg, secret) {
			t.Errorf("the secret reached argv: %q", arg)
		}
	}
}

func asMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok {
			out[name] = value // last wins, matching a child process's getenv
		}
	}
	return out
}
