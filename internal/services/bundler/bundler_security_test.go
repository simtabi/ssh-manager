package bundler

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// tmpResidue lists every regular file currently under dir, so a test can assert
// that no plaintext was staged there.
func tmpResidue(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			found = append(found, rel)
		}
		return nil
	})
	return found
}

// watchingCipher is an identity copy that snapshots the temp dir at the moment
// the cipher is invoked - the point where a staging implementation would have
// just finished writing the plaintext archive.
type watchingCipher struct {
	t      *testing.T
	tmpDir string
	seen   *[]string
}

func (c watchingCipher) Encrypt(dst io.Writer, src io.Reader, _ string) error {
	*c.seen = append(*c.seen, tmpResidue(c.t, c.tmpDir)...)
	_, err := io.Copy(dst, src)
	return err
}

func (c watchingCipher) Decrypt(dst io.Writer, src io.Reader, _ string) error {
	_, err := io.Copy(dst, src)
	return err
}

// $TMPDIR is world-traversable, frequently on a different filesystem than the
// one holding ~/.ssh, and survives a crash. A private key must never land there.
func TestBundleStagesNoPlaintext(t *testing.T) {
	ssh, cfg := writeSrc(t)
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	var seen []string
	b := New(ssh, cfg, watchingCipher{t: t, tmpDir: tmpDir, seen: &seen})
	if _, err := b.Bundle("age1fake", filepath.Join(t.TempDir(), "out"), "20260101"); err != nil {
		t.Fatal(err)
	}
	if len(seen) > 0 {
		t.Errorf("plaintext was staged in the temp dir before encryption: %v", seen)
	}
	if left := tmpResidue(t, tmpDir); len(left) > 0 {
		t.Errorf("temp residue left after bundling: %v", left)
	}
}

func TestRestoreStagesNoPlaintext(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := filepath.Join(t.TempDir(), "out")
	res, err := New(ssh, cfg, fakeCipher{}).Bundle("age1fake", dest, "20260101")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	base := t.TempDir()
	// Sampled from inside lay-down, by which point a staging implementation has
	// both the decrypted tar and the extracted tree on disk.
	var duringLayDown []string
	fp := func(p string) (string, error) {
		duringLayDown = append(duringLayDown, tmpResidue(t, tmpDir)...)
		return "SHA256:fake", nil
	}
	if _, err := New(filepath.Join(base, ".ssh"), filepath.Join(base, "cfg"), fakeCipher{}).
		Restore(res.AgePath, "", fp); err != nil {
		t.Fatal(err)
	}
	if len(duringLayDown) > 0 {
		t.Errorf("decrypted plaintext was staged in the temp dir: %v", duringLayDown)
	}
	if left := tmpResidue(t, tmpDir); len(left) > 0 {
		t.Errorf("temp residue left after restoring: %v", left)
	}
}

func TestBundleIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	ssh, cfg := writeSrc(t)
	res, err := New(ssh, cfg, fakeCipher{}).Bundle("age1fake", filepath.Join(t.TempDir(), "out"), "20260101")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{res.AgePath, res.AgePath + ".sha256", res.AgePath + ".contents"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %o, want 0600", filepath.Base(p), fi.Mode().Perm())
		}
	}
}

// failingCipher stands in for age exiting non-zero (missing binary, bad
// recipient). The half-written output must not survive to be trusted later.
type failingCipher struct{}

func (failingCipher) Encrypt(dst io.Writer, src io.Reader, _ string) error {
	_, _ = io.CopyN(dst, src, 16)
	return io.ErrUnexpectedEOF
}

func (failingCipher) Decrypt(dst io.Writer, src io.Reader, _ string) error {
	return io.ErrUnexpectedEOF
}

func TestFailedEncryptLeavesNoBundle(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := filepath.Join(t.TempDir(), "out")
	if _, err := New(ssh, cfg, failingCipher{}).Bundle("age1fake", dest, "20260101"); err == nil {
		t.Fatal("expected the encrypt failure to surface")
	}
	if _, err := os.Stat(filepath.Join(dest, "ssh-manager-20260101.age")); !os.IsNotExist(err) {
		t.Error("a partial bundle was left behind and would look restorable")
	}
}

func TestDecryptFailureIsReportedAsSuch(t *testing.T) {
	ssh, cfg := writeSrc(t)
	dest := filepath.Join(t.TempDir(), "out")
	res, err := New(ssh, cfg, fakeCipher{}).Bundle("age1fake", dest, "20260101")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	_, err = New(filepath.Join(base, ".ssh"), filepath.Join(base, "cfg"), failingCipher{}).
		Restore(res.AgePath, "", fakeFP)
	if err == nil {
		t.Fatal("expected the decrypt failure to surface")
	}
	// The cipher error is the root cause; reporting "corrupt archive" would send
	// the user looking at the wrong thing when their identity file is simply wrong.
	if strings.Contains(err.Error(), "corrupt") {
		t.Errorf("decrypt failure was misreported as corruption: %v", err)
	}
}

// writeArchive builds a bundle by hand so a member name can be crafted.
func writeArchive(t *testing.T, dir string, names ...string) string {
	t.Helper()
	agePath := filepath.Join(dir, "ssh-manager-crafted.age")
	f, err := os.Create(agePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("OWNED\n")
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []io.Closer{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return agePath
}

func TestRestoreRefusesEscapingMembers(t *testing.T) {
	for _, name := range []string{
		"ssh/../../../../etc/evil",
		"config/../../evil",
		"../evil",
		"/etc/evil",
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			ssh := filepath.Join(base, ".ssh")
			cfg := filepath.Join(base, "cfg")
			crafted := writeArchive(t, t.TempDir(), name)

			if _, err := New(ssh, cfg, fakeCipher{}).Restore(crafted, "", fakeFP); err == nil {
				t.Error("a member pointing outside the managed tree was accepted")
			}
			outside := filepath.Join(base, "evil")
			if _, err := os.Stat(outside); err == nil {
				t.Error("a file was written outside the managed tree")
			}
		})
	}
}
