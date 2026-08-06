package bundler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fake cipher exercises the tar and lay-down logic but not the pipe wiring
// against a real subprocess, which is where a streaming refactor actually breaks:
// a deadlock or a truncated stream only shows up with a process on the other end.
func TestAgeRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not installed")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not installed")
	}
	ssh, cfg := writeSrc(t)

	identity := filepath.Join(t.TempDir(), "id.age")
	out, err := exec.Command("age-keygen", "-o", identity).CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v: %s", err, out)
	}
	var recipient string
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "age1") {
			recipient = f
		}
	}
	if recipient == "" {
		t.Fatalf("no recipient in age-keygen output: %s", out)
	}

	res, err := New(ssh, cfg, AgeCipher{}).Bundle(recipient, filepath.Join(t.TempDir(), "out"), "20260101")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(res.AgePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIV-A") {
		t.Fatal("the bundle contains the key in the clear")
	}

	base := t.TempDir()
	rr, err := New(filepath.Join(base, ".ssh"), filepath.Join(base, "cfg"), AgeCipher{}).
		Restore(res.AgePath, identity, fakeFP)
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Restored) != len(res.Contents) {
		t.Errorf("restored %d file(s), bundled %d", len(rr.Restored), len(res.Contents))
	}
	got, err := os.ReadFile(filepath.Join(base, ".ssh", "profiles", "work", "work_a-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "PRIV-A\n" {
		t.Errorf("key did not survive the round trip: %q", got)
	}
}

// A wrong identity must be reported as a decryption failure, and must not leave
// a partially overwritten tree behind.
func TestAgeWrongIdentity(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not installed")
	}
	ssh, cfg := writeSrc(t)
	keys := t.TempDir()

	recipientFor := func(name string) (identity, recipient string) {
		identity = filepath.Join(keys, name)
		out, err := exec.Command("age-keygen", "-o", identity).CombinedOutput()
		if err != nil {
			t.Fatalf("age-keygen: %v: %s", err, out)
		}
		for _, f := range strings.Fields(string(out)) {
			if strings.HasPrefix(f, "age1") {
				recipient = f
			}
		}
		return identity, recipient
	}
	_, recipient := recipientFor("right.age")
	wrong, _ := recipientFor("wrong.age")

	res, err := New(ssh, cfg, AgeCipher{}).Bundle(recipient, filepath.Join(t.TempDir(), "out"), "20260101")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if _, err := New(filepath.Join(base, ".ssh"), filepath.Join(base, "cfg"), AgeCipher{}).
		Restore(res.AgePath, wrong, fakeFP); err == nil {
		t.Fatal("restoring with the wrong identity should fail")
	}
	if _, err := os.Stat(filepath.Join(base, ".ssh")); err == nil {
		t.Error("a failed decrypt still laid files down")
	}
}
