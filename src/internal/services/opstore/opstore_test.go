package opstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const itemJSON = `{"id":"abc123","title":"simtabi_github-ed25519","vault":{"id":"v1","name":"Simtabi"},
 "category":"SSH_KEY","fields":[
  {"id":"private_key","label":"private key","value":""},
  {"id":"public_key","label":"public key","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
  {"id":"fingerprint","label":"fingerprint","value":"SHA256:abc"},
  {"id":"key_type","label":"key type","value":"ed25519"}]}`

// fakeOp writes an op that logs its argv and runs body, and returns a client
// for it plus the log path.
func fakeOp(t *testing.T, body string) (*Client, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake op is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\" >> " + log + "; done\necho >> " + log + "\n" + body
	bin := filepath.Join(dir, "op")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Client{Bin: bin}, log
}

func TestCreateReturnsThePublicKeyAndNeverAsksForThePrivateOne(t *testing.T) {
	c, log := fakeOp(t, "cat <<'J'\n"+itemJSON+"\nJ\n")
	it, err := c.Create("Simtabi", "simtabi_github-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if it.ID != "abc123" || it.PublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample" || it.Fingerprint != "SHA256:abc" {
		t.Errorf("item = %+v", it)
	}
	argv, _ := os.ReadFile(log)
	want := "[item][create][--category][ssh][--title][simtabi_github-ed25519][--vault][Simtabi][--format][json]"
	if !strings.Contains(string(argv), want) {
		t.Errorf("argv = %s, want %s", argv, want)
	}
	if strings.Contains(string(argv), "private") || strings.Contains(string(argv), "reveal") {
		t.Errorf("sshmgr must never read a private key out of 1Password: %s", argv)
	}
}

func TestGetReportsAMissingItemAsNotFound(t *testing.T) {
	c, _ := fakeOp(t, `echo '[ERROR] 2026/10/19 "x" isn'"'"'t an item in the "Simtabi" vault.' >&2; exit 1`+"\n")
	_, err := c.Get("Simtabi", "x")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestGetSurfacesOtherFailures(t *testing.T) {
	c, _ := fakeOp(t, "echo '[ERROR] account is not signed in' >&2; exit 1\n")
	_, err := c.Get("Simtabi", "x")
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("err = %v, want the op error, not ErrNotFound", err)
	}
}

func TestPublicKeyFieldIsMatchedByLabelToo(t *testing.T) {
	it, err := parseItem([]byte(`{"id":"i","title":"t","fields":[{"id":"x1","label":"Public Key","value":"ssh-ed25519 AAAA k"}]}`))
	if err != nil || it.PublicKey != "ssh-ed25519 AAAA k" {
		t.Fatalf("item = %+v, err = %v", it, err)
	}
}

func TestEditAndArchiveAddressTheItemByID(t *testing.T) {
	c, log := fakeOp(t, "exit 0\n")
	if err := c.Rename("Simtabi", "abc123", "simtabi_github-ed25519.old"); err != nil {
		t.Fatal(err)
	}
	if err := c.Archive("Simtabi", "abc123"); err != nil {
		t.Fatal(err)
	}
	argv, _ := os.ReadFile(log)
	for _, want := range []string{
		"[item][edit][abc123][--vault][Simtabi][--title][simtabi_github-ed25519.old]",
		"[item][delete][abc123][--vault][Simtabi][--archive]",
	} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("argv = %s, want %s", argv, want)
		}
	}
}
