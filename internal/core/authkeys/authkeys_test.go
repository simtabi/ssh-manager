package authkeys

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// ed25519Body builds a base64 body that decodes to a real ed25519 wire blob.
func ed25519Body(fill byte) string {
	t := []byte("ssh-ed25519")
	var blob []byte
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(t)))
	blob = append(blob, t...)
	blob = binary.BigEndian.AppendUint32(blob, 32)
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return base64.StdEncoding.EncodeToString(append(blob, key...))
}

func TestValidityAndBody(t *testing.T) {
	body := ed25519Body(1)
	valid := "ssh-ed25519 " + body + " me@host"
	if !IsValidPublicKey(valid) {
		t.Fatal("a real ed25519 line should be valid")
	}
	if KeyBody(valid) != body {
		t.Fatalf("KeyBody = %q, want %q", KeyBody(valid), body)
	}
	// options-prefixed line is still a valid key
	opts := `command="x",no-pty ssh-ed25519 ` + body + " ops"
	if !IsValidPublicKey(opts) || KeyBody(opts) != body {
		t.Fatal("options-prefixed key line should parse with the same body")
	}
	for _, junk := range []string{
		"",
		"# a comment",
		"ssh-ed25519 not-base64!!! c",
		"ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("hello world not a key")) + " c",
		"random words here",
	} {
		if IsValidPublicKey(junk) {
			t.Errorf("junk line should be invalid: %q", junk)
		}
		if KeyBody(junk) != "" {
			t.Errorf("junk line should have empty body: %q", junk)
		}
	}
}

func TestSameKeyAndCount(t *testing.T) {
	b1, b2 := ed25519Body(1), ed25519Body(2)
	if !SameKey("ssh-ed25519 "+b1+" a", "ssh-ed25519 "+b1+" different-comment") {
		t.Error("same body, different comment must be SameKey")
	}
	if SameKey("ssh-ed25519 "+b1+" a", "ssh-ed25519 "+b2+" a") {
		t.Error("different bodies must not be SameKey")
	}
	text := "# header\nssh-ed25519 " + b1 + " a\n\nssh-ed25519 " + b2 + " b\njunk line\n"
	if CountKeys(text) != 2 {
		t.Fatalf("CountKeys = %d, want 2", CountKeys(text))
	}
}

func TestAddRemove(t *testing.T) {
	b1, b2 := ed25519Body(1), ed25519Body(2)
	line1 := "ssh-ed25519 " + b1 + " a"
	text := line1 + "\n"

	// adding a present body (different comment) is a no-op
	out, added, err := AddKeyToText(text, "ssh-ed25519 "+b1+" other")
	if err != nil || added || out != text {
		t.Fatalf("re-add should be a no-op: added=%v err=%v", added, err)
	}
	// adding a new body appends
	out, added, err = AddKeyToText(text, "ssh-ed25519 "+b2+" b")
	if err != nil || !added || CountKeys(out) != 2 {
		t.Fatalf("add new should append: added=%v err=%v count=%d", added, err, CountKeys(out))
	}
	// junk is rejected
	if _, _, err := AddKeyToText(text, "not a key"); err == nil {
		t.Error("adding a non-key must error")
	}
	// remove by body ignores the comment
	out2, removed := RemoveKeyFromText(out, "ssh-ed25519 "+b1+" any-comment")
	if removed != 1 {
		t.Fatalf("remove should drop exactly 1, got %d", removed)
	}
	if CountKeys(out2) != 1 {
		t.Fatalf("one key should remain, got %d", CountKeys(out2))
	}
	if _, removed := RemoveKeyFromText(out2, "junk"); removed != 0 {
		t.Errorf("removing a non-key removes nothing, got %d", removed)
	}
}

// A length prefix above MaxInt32 must be rejected, not trusted.
//
// The prefix is attacker-controlled: it comes out of an authorized_keys file,
// which on a shared box anyone with write access can craft. On a 32-bit build -
// sshmgr ships 386, armv6 and armv7 (build/targets.txt) - `int` is 32 bits, so
// the old `4+int(n) > len(blob)` check converted such a prefix to a negative,
// passed, and then panicked slicing with a negative bound. This asserts the
// rejection; the point is that it returns rather than crashes.
func TestLengthPrefixPastTheBlobIsRejected(t *testing.T) {
	for _, prefix := range []uint32{0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 1 << 20, 0} {
		blob := make([]byte, 64)
		binary.BigEndian.PutUint32(blob[:4], prefix)
		copy(blob[4:], "ssh-ed25519")
		line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
		if IsValidPublicKey(line) {
			t.Errorf("prefix %#x should not parse as a key", prefix)
		}
	}
}

// A line that claims one type but whose blob encodes another is not a key. This
// is the check that stops base64-looking junk from being trusted.
func TestTypeTokenMustMatchTheEncodedWireType(t *testing.T) {
	body := ed25519Body(3) // encodes "ssh-ed25519"
	if IsValidPublicKey("ssh-rsa " + body + " mismatched") {
		t.Error("a line claiming ssh-rsa over an ed25519 blob should not parse")
	}
	if !IsValidPublicKey("ssh-ed25519 " + body + " honest") {
		t.Error("the same body under its real type should parse")
	}
}

// Add/remove normalise whitespace the way the Python did: an empty file gains no
// leading blank line, an unterminated file gains its newline, and a file emptied
// of keys comes back empty rather than as a lone newline.
func TestAddRemoveNormaliseFileEdges(t *testing.T) {
	b1, b2 := ed25519Body(4), ed25519Body(5)
	line1, line2 := "ssh-ed25519 "+b1+" a", "ssh-ed25519 "+b2+" b"

	out, added, err := AddKeyToText("", line1)
	if err != nil || !added {
		t.Fatalf("add to empty: added=%v err=%v", added, err)
	}
	if out != line1+"\n" {
		t.Errorf("add to empty = %q, want no leading blank line", out)
	}

	out, added, err = AddKeyToText(line1, line2) // no trailing newline in
	if err != nil || !added {
		t.Fatalf("add to unterminated: added=%v err=%v", added, err)
	}
	if out != line1+"\n"+line2+"\n" {
		t.Errorf("add to unterminated = %q, want a normalised two-line file", out)
	}

	if out, removed := RemoveKeyFromText(line1+"\n", line1); removed != 1 || out != "" {
		t.Errorf("emptying a file = %q (removed %d), want an empty string", out, removed)
	}
	// Every copy of a duplicated key goes.
	if out, removed := RemoveKeyFromText(line1+"\n"+line1+"\n", line1); removed != 2 || out != "" {
		t.Errorf("duplicate removal = %q (removed %d), want both gone", out, removed)
	}
}

// An authorized_keys copied off a Windows box still parses, and removal does not
// leave stray carriage returns behind.
func TestCRLFInputIsNormalised(t *testing.T) {
	line := "ssh-ed25519 " + ed25519Body(6) + " a"
	if n := CountKeys(line + "\r\n"); n != 1 {
		t.Errorf("CountKeys with CRLF = %d, want 1", n)
	}
	if out, removed := RemoveKeyFromText(line+"\r\n", line); removed != 1 || out != "" {
		t.Errorf("CRLF removal: out=%q removed=%d", out, removed)
	}
}
