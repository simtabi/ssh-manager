package bundler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCipher is an identity copy - lets the tar / lay-down / checksum logic be
// tested without age installed (mirrors the Python tests' injected fake).
type fakeCipher struct{}

func (fakeCipher) Encrypt(src, dst, _ string) error { return cp(src, dst) }
func (fakeCipher) Decrypt(src, dst, _, _ string) error {
	return cp(src, dst)
}
func cp(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func fakeFP(path string) (string, error) { return "SHA256:fake-" + filepath.Base(path), nil }

func writeSrc(t *testing.T) (ssh, cfg string) {
	t.Helper()
	base := t.TempDir()
	ssh = filepath.Join(base, ".ssh")
	cfg = filepath.Join(base, "cfg")
	mk := func(p, c string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk(filepath.Join(ssh, "profiles", "work", "work_a-ed25519"), "PRIV-A\n")
	mk(filepath.Join(ssh, "profiles", "work", "work_a-ed25519.pub"), "ssh-ed25519 AAAA a\n")
	mk(filepath.Join(ssh, "profiles", "work", ".staging", "junk"), "STAGING\n") // excluded
	mk(filepath.Join(cfg, "manifest.json"), `{"v":1}`)
	mk(filepath.Join(cfg, "inventory.json"), `{"v":1}`)
	mk(filepath.Join(cfg, ".env"), "SECRET=x\n") // excluded
	return ssh, cfg
}

func TestBundleContentsAndRoundTrip(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := t.TempDir()
	b := New(ssh, cfg, fakeCipher{})

	res, err := b.Bundle("age1recipient", dest, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ssh/profiles/work/work_a-ed25519",
		"ssh/profiles/work/work_a-ed25519.pub",
		"config/manifest.json",
		"config/inventory.json",
	}
	if strings.Join(res.Contents, ",") != strings.Join(want, ",") {
		t.Fatalf("contents = %v\nwant %v (no .env, no .staging, no providers.json since absent)", res.Contents, want)
	}
	if !strings.HasPrefix(res.SHA256, "sha256:") {
		t.Errorf("sha256 = %q", res.SHA256)
	}
	// Sidecars written.
	if b, _ := os.ReadFile(res.AgePath + ".contents"); strings.Count(string(b), "\n") != len(want) {
		t.Errorf(".contents sidecar wrong:\n%s", b)
	}
	if b, _ := os.ReadFile(res.AgePath + ".sha256"); !strings.HasSuffix(strings.TrimSpace(string(b)), filepath.Base(res.AgePath)) {
		t.Errorf(".sha256 sidecar wrong: %s", b)
	}

	// Restore into a fresh home.
	base2 := t.TempDir()
	ssh2, cfg2 := filepath.Join(base2, ".ssh"), filepath.Join(base2, "cfg")
	rr, err := New(ssh2, cfg2, fakeCipher{}).Restore(res.AgePath, "", "", fakeFP)
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Restored) != len(want) {
		t.Errorf("restored %d files want %d", len(rr.Restored), len(want))
	}
	priv, _ := os.ReadFile(filepath.Join(ssh2, "profiles", "work", "work_a-ed25519"))
	if string(priv) != "PRIV-A\n" {
		t.Errorf("private key not laid back: %q", priv)
	}
	if _, err := os.Stat(filepath.Join(cfg2, ".env")); err == nil {
		t.Error(".env must not be in the bundle/restore")
	}
	if len(rr.Fingerprints) != 1 || rr.Fingerprints[0].Name != "work_a-ed25519" {
		t.Errorf("fingerprints = %+v", rr.Fingerprints)
	}
}

func TestBundleNeedsRecipient(t *testing.T) {
	ssh, cfg := writeSrc(t)
	if _, err := New(ssh, cfg, fakeCipher{}).Bundle("", t.TempDir(), "TS"); err == nil {
		t.Error("empty recipient should error")
	}
}

func TestRestoreRefusesOnChecksumMismatch(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := t.TempDir()
	res, err := New(ssh, cfg, fakeCipher{}).Bundle("r", dest, "TS")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the bundle after the sidecar was written.
	os.WriteFile(res.AgePath, []byte("tampered"), 0o600)
	if _, err := New(ssh, cfg, fakeCipher{}).Restore(res.AgePath, "", "", fakeFP); err == nil ||
		!strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("tampered bundle should fail checksum, got %v", err)
	}
}
