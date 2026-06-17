package keystore

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func requireTool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
}

func TestGenerateIdempotentAndDerive(t *testing.T) {
	requireTool(t)
	dir := t.TempDir()
	priv := filepath.Join(dir, "sub", "id_ed25519") // nested dir is created
	ks := New()

	res, err := ks.Generate(priv, "ed25519", "test@parity", "", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !res.Created {
		t.Error("first generate should report Created=true")
	}
	if !strings.HasPrefix(res.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint=%q", res.Fingerprint)
	}
	if _, err := os.Stat(priv + ".pub"); err != nil {
		t.Errorf("public key not written: %v", err)
	}

	// Perms (POSIX only): private 0600, public 0644, dir 0700.
	if runtime.GOOS != "windows" {
		assertMode(t, priv, 0o600)
		assertMode(t, priv+".pub", 0o644)
		assertMode(t, filepath.Dir(priv), 0o700)
	}

	// Idempotent, non-destructive: re-run keeps the key and returns Created=false
	// with the same fingerprint.
	res2, err := ks.Generate(priv, "ed25519", "different-comment", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Created {
		t.Error("second generate should report Created=false (kept existing)")
	}
	if res2.Fingerprint != res.Fingerprint {
		t.Errorf("fingerprint changed on re-run: %q -> %q", res.Fingerprint, res2.Fingerprint)
	}

	// Fingerprint of the public key matches the private key's.
	pubFP, err := ks.Fingerprint(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if pubFP != res.Fingerprint {
		t.Errorf("pub fingerprint %q != priv %q", pubFP, res.Fingerprint)
	}

	// Derive the public key from the private material; it matches the .pub file's
	// key body (type + base64; comments may differ).
	derived, encrypted, err := ks.PublicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		t.Error("unencrypted key reported encrypted")
	}
	onDisk, _ := os.ReadFile(priv + ".pub")
	if keyBody(derived) != keyBody(string(onDisk)) {
		t.Errorf("derived pub body != on-disk\n derived=%q\n disk=%q", derived, string(onDisk))
	}
}

func TestPublicFromPrivateInvalid(t *testing.T) {
	requireTool(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "garbage")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, encrypted, err := New().PublicFromPrivate(bad)
	if err != nil {
		t.Fatal(err)
	}
	if pub != "" || encrypted {
		t.Errorf("garbage should be ('', false), got (%q, %v)", pub, encrypted)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode=%o want %o", path, got, want)
	}
}

// keyBody returns "<type> <base64>" without the trailing comment.
func keyBody(line string) string {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) >= 2 {
		return f[0] + " " + f[1]
	}
	return strings.TrimSpace(line)
}
