package bundler

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCipher is an identity copy - lets the tar / lay-down / checksum logic be
// tested without age installed.
type fakeCipher struct{}

func (fakeCipher) Encrypt(dst io.Writer, src io.Reader, _ string) error {
	_, err := io.Copy(dst, src)
	return err
}

func (fakeCipher) Decrypt(dst io.Writer, src io.Reader, _ string) error {
	_, err := io.Copy(dst, src)
	return err
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
	rr, err := New(ssh2, cfg2, fakeCipher{}).Restore(res.AgePath, "", fakeFP)
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
	_ = os.WriteFile(res.AgePath, []byte("tampered"), 0o600)
	if _, err := New(ssh, cfg, fakeCipher{}).Restore(res.AgePath, "", fakeFP); err == nil ||
		!strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("tampered bundle should fail checksum, got %v", err)
	}
}

// Restore overlays; it never clears the destination first.
//
// This is the property that stops a restore from being a way to lose keys. A
// bundle holds what it holds; a key on disk that the bundle does not contain -
// minted after the bundle was taken, or belonging to a profile added since -
// must survive, because the bundle has no copy to put back.
func TestRestoreOverlaysAndKeepsWhatItCannotReplace(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := t.TempDir()
	res, err := New(ssh, cfg, fakeCipher{}).Bundle("age1recipient", dest, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}

	// A destination that already holds a key the bundle knows nothing about,
	// and a newer version of one it does.
	base2 := t.TempDir()
	ssh2, cfg2 := filepath.Join(base2, ".ssh"), filepath.Join(base2, "cfg")
	mk := func(p, c string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newer := filepath.Join(ssh2, "profiles", "later", "later_key-ed25519")
	mk(newer, "MINTED-AFTER-THE-BUNDLE\n")
	mk(filepath.Join(ssh2, "profiles", "work", "work_a-ed25519"), "STALE\n")

	if _, err := New(ssh2, cfg2, fakeCipher{}).Restore(res.AgePath, "", fakeFP); err != nil {
		t.Fatal(err)
	}

	// The key the bundle never had is still there, unchanged.
	got, err := os.ReadFile(newer)
	if err != nil {
		t.Fatalf("restore deleted a key the bundle had no copy of: %v", err)
	}
	if string(got) != "MINTED-AFTER-THE-BUNDLE\n" {
		t.Errorf("an untouched key was modified: %q", got)
	}
	// The key the bundle did have was replaced by the bundle's copy.
	got, err = os.ReadFile(filepath.Join(ssh2, "profiles", "work", "work_a-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "PRIV-A\n" {
		t.Errorf("the bundled key was not laid back over the stale one: %q", got)
	}
}
