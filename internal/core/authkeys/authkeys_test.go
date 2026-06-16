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
	if removed != 1 || CountKeys(out2) != 1 || KeyBody(out2) == "" && CountKeys(out2) != 1 {
		t.Fatalf("remove should drop 1, leaving 1: removed=%d count=%d", removed, CountKeys(out2))
	}
	if removed2 := 0; func() bool { _, removed2 = RemoveKeyFromText(out2, "junk"); return removed2 != 0 }() {
		t.Errorf("removing a non-key removes nothing, got %d", removed2)
	}
}
