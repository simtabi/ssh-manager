package platform

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Parity reference: v1's platform layer, which dispatched through a class per
// OS. The Go equivalent is build-tagged files plus these predicates (redesign R7).

// writeToPipe returns a read end preloaded with s, for exercising ReadLine
// against a real *os.File the way stdin is one.
func writeToPipe(t *testing.T, s string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.WriteString(s)
		_ = w.Close()
	}()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// ReadLine stops at the newline and leaves the rest in the file. Callers read a
// second line to confirm a passphrase, so consuming past the newline - which a
// buffered reader would do - would swallow the confirmation.
func TestReadLineStopsAtTheNewlineAndLeavesTheRest(t *testing.T) {
	f := writeToPipe(t, "first\nsecond\n")

	got, err := ReadLine(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "first" {
		t.Errorf("first line = %q", got)
	}
	got, err = ReadLine(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Errorf("second line = %q; the first read swallowed it", got)
	}
}

// A passphrase is taken verbatim apart from the line ending: spaces are
// significant, and a CRLF terminal must not leave a carriage return on the end.
func TestReadLinePreservesContentButStripsCR(t *testing.T) {
	cases := map[string]string{
		"plain\n":                    "plain",
		"with spaces  \n":            "with spaces  ",
		"crlf\r\n":                   "crlf",
		"\n":                         "",
		"no trailing newline":        "no trailing newline",
		"punctuation !@#$%^&*()_+\n": "punctuation !@#$%^&*()_+",
	}
	for in, want := range cases {
		got, err := ReadLine(writeToPipe(t, in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ReadLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// An empty input ends cleanly rather than blocking or erroring: a closed stdin
// is a legitimate way to decline a prompt.
func TestReadLineOnClosedInput(t *testing.T) {
	got, err := ReadLine(writeToPipe(t, ""))
	if err != nil {
		t.Fatalf("EOF should not be an error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// Exactly one predicate is true, and it agrees with the toolchain.
func TestOSPredicatesAgreeWithGOOS(t *testing.T) {
	n := 0
	for _, b := range []bool{IsMacOS(), IsLinux(), IsWindows()} {
		if b {
			n++
		}
	}
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		if n != 1 {
			t.Errorf("%d predicates true on %s, want exactly 1", n, runtime.GOOS)
		}
		if !FirstClass() {
			t.Errorf("%s is a first-class platform", runtime.GOOS)
		}
	default:
		if n != 0 || FirstClass() {
			t.Errorf("%s is not first-class: predicates=%d firstClass=%v", runtime.GOOS, n, FirstClass())
		}
	}

	if IsMacOS() != (runtime.GOOS == "darwin") {
		t.Error("IsMacOS disagrees with GOOS")
	}
	if IsWindows() != (runtime.GOOS == "windows") {
		t.Error("IsWindows disagrees with GOOS")
	}
}

// UseKeychain is an Apple extension. Emitting it elsewhere is not a cosmetic
// error: an unknown keyword is a hard parse failure for the whole ssh config,
// which would break every host at once.
func TestEmitUseKeychainOnlyOnMacOS(t *testing.T) {
	if EmitUseKeychain() != IsMacOS() {
		t.Errorf("EmitUseKeychain()=%v on %s", EmitUseKeychain(), runtime.GOOS)
	}
}

// The OS line is pasted into bug reports, so it carries both the token a
// developer greps for and a name a user recognises.
func TestOSNameCarriesBothForms(t *testing.T) {
	name := OSName()
	if !strings.HasPrefix(name, runtime.GOOS) {
		t.Errorf("OSName = %q, should start with the GOOS token", name)
	}
	if !strings.Contains(name, "(") || !strings.HasSuffix(name, ")") {
		t.Errorf("OSName = %q, should carry a human name in parentheses", name)
	}
	pretty := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
	if want, ok := pretty[runtime.GOOS]; ok && !strings.Contains(name, want) {
		t.Errorf("OSName = %q, should contain %q", name, want)
	}
}

// Under `go test` stdin is not a terminal, so the no-echo read has to say so
// rather than hang or read the passphrase with echo on. Callers use this to
// fall back to a piped line.
func TestReadSecretRefusesWithoutATerminal(t *testing.T) {
	if StdinIsTerminal() {
		t.Skip("stdin is a terminal here, so the fallback cannot be exercised")
	}
	_, err := ReadSecret("passphrase: ")
	if !errors.Is(err, ErrNotATerminal) {
		t.Errorf("err = %v, want ErrNotATerminal so the caller can fall back", err)
	}
}
