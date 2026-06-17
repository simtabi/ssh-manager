// Package bundler makes and restores an age-encrypted backup, ported from
// services/bundler.py. bundle tars {private keys + manifest + inventory +
// providers.json} (NEVER .env) and age-encrypts it with a SHA256 sidecar + a
// contents list; restore decrypts and lays the SAME keys back (same fingerprint).
// The cipher is behind a seam (Cipher) so tests inject a fake and the tar /
// lay-down / fingerprint guarantees are verifiable without age installed.
package bundler

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const ageHint = "install age: brew install age  (Linux: apt install age / get from FiloSottile/age)"

const (
	sshPrefix    = "ssh/"
	configPrefix = "config/"
)

var configMembers = []string{"manifest.json", "inventory.json", "providers.json"}

// Cipher encrypts/decrypts a file. Production uses AgeCipher; tests inject a fake.
type Cipher interface {
	Encrypt(src, dst, recipient string) error
	Decrypt(src, dst, identityFile, passphrase string) error
}

// AgeCipher shells out to age (X25519 + ChaCha20-Poly1305), file-based.
type AgeCipher struct{}

func (AgeCipher) Encrypt(src, dst, recipient string) error {
	if err := requireAge(); err != nil {
		return err
	}
	return run("age", "-r", recipient, "-o", dst, src)
}

func (AgeCipher) Decrypt(src, dst, identityFile, _ string) error {
	if err := requireAge(); err != nil {
		return err
	}
	args := []string{"-d", "-o", dst}
	if identityFile != "" {
		args = append(args, "-i", identityFile)
	}
	args = append(args, src)
	return run("age", args...)
}

func requireAge() error {
	if _, err := exec.LookPath("age"); err != nil {
		return fmt.Errorf("age not found: %s", ageHint)
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s: %s", name, msg)
		}
		return err
	}
	return nil
}

// BundleResult summarizes a bundle run.
type BundleResult struct {
	AgePath  string
	SHA256   string
	Contents []string
}

// Format renders the bundle summary (mirrors BundleResult.format).
func (r BundleResult) Format() string {
	lines := []string{
		"bundle: " + r.AgePath,
		"  sha256: " + r.SHA256,
		fmt.Sprintf("  contents (%d files; .env excluded):", len(r.Contents)),
	}
	for _, c := range r.Contents {
		lines = append(lines, "    "+c)
	}
	return strings.Join(lines, "\n")
}

// FP is one restored key's fingerprint (ordered by lay-down).
type FP struct{ Name, Fingerprint string }

// RestoreResult summarizes a restore run.
type RestoreResult struct {
	Restored     []string
	Fingerprints []FP
}

// Format renders the restore summary (mirrors RestoreResult.format).
func (r RestoreResult) Format() string {
	lines := []string{fmt.Sprintf("restore: laid down %d file(s)", len(r.Restored))}
	for _, f := range r.Fingerprints {
		lines = append(lines, "  "+f.Name+"  "+f.Fingerprint)
	}
	return strings.Join(lines, "\n")
}

// Bundler makes/restores bundles.
type Bundler struct {
	sshDir, configDir string
	cipher            Cipher
}

// New builds a Bundler.
func New(sshDir, configDir string, cipher Cipher) *Bundler {
	return &Bundler{sshDir: sshDir, configDir: configDir, cipher: cipher}
}

// Bundle tars the keys + config models, encrypts to dest/ssh-manager-<stamp>.age,
// and writes the .sha256 + .contents sidecars. Mirrors Bundler.bundle.
func (b *Bundler) Bundle(recipient, destDir, stamp string) (BundleResult, error) {
	if recipient == "" {
		return BundleResult{}, fmt.Errorf("no age recipient - set SSH_MANAGER_AGE_RECIPIENT or pass --recipient")
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return BundleResult{}, err
	}
	tmp, err := os.MkdirTemp("", "sshmgr-bundle-")
	if err != nil {
		return BundleResult{}, err
	}
	defer os.RemoveAll(tmp)
	tarPath := filepath.Join(tmp, "bundle.tar.gz")
	contents, err := b.buildTar(tarPath)
	if err != nil {
		return BundleResult{}, err
	}
	agePath := filepath.Join(destDir, "ssh-manager-"+stamp+".age")
	if err := b.cipher.Encrypt(tarPath, agePath, recipient); err != nil {
		return BundleResult{}, err
	}
	sha, err := sha256File(agePath)
	if err != nil {
		return BundleResult{}, err
	}
	name := filepath.Base(agePath)
	if err := os.WriteFile(agePath+".sha256", []byte(sha+"  "+name+"\n"), 0o600); err != nil {
		return BundleResult{}, err
	}
	if err := os.WriteFile(agePath+".contents", []byte(strings.Join(contents, "\n")+"\n"), 0o600); err != nil {
		return BundleResult{}, err
	}
	return BundleResult{AgePath: agePath, SHA256: sha, Contents: contents}, nil
}

func (b *Bundler) buildTar(tarPath string) ([]string, error) {
	f, err := os.OpenFile(tarPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	var members []string

	profiles := filepath.Join(b.sshDir, "profiles")
	if fi, err := os.Stat(profiles); err == nil && fi.IsDir() {
		var paths []string
		_ = filepath.WalkDir(profiles, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				paths = append(paths, p)
			}
			return nil
		})
		sort.Strings(paths)
		for _, p := range paths {
			rel, _ := filepath.Rel(b.sshDir, p)
			rel = filepath.ToSlash(rel)
			if hasStaging(rel) {
				continue
			}
			arc := sshPrefix + rel
			if err := addFile(tw, p, arc); err != nil {
				closeAll(tw, gz, f)
				return nil, err
			}
			members = append(members, arc)
		}
	}
	for _, name := range configMembers { // NEVER .env
		src := filepath.Join(b.configDir, name)
		if _, err := os.Stat(src); err == nil {
			arc := configPrefix + name
			if err := addFile(tw, src, arc); err != nil {
				closeAll(tw, gz, f)
				return nil, err
			}
			members = append(members, arc)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return members, f.Close()
}

func hasStaging(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if part == ".staging" {
			return true
		}
	}
	return false
}

func addFile(tw *tar.Writer, path, arc string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = arc
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	_, err = io.Copy(tw, src)
	return err
}

func closeAll(tw *tar.Writer, gz *gzip.Writer, f *os.File) {
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()
}

// Restore decrypts bundlePath and lays the same keys back down (verifying the
// SHA256 sidecar first). fingerprintOf fingerprints each restored .pub. Mirrors
// Bundler.restore.
func (b *Bundler) Restore(bundlePath, identityFile, passphrase string, fingerprintOf func(string) (string, error)) (RestoreResult, error) {
	if _, err := os.Stat(bundlePath); err != nil {
		return RestoreResult{}, fmt.Errorf("bundle not found: %s", bundlePath)
	}
	if err := verifyChecksum(bundlePath); err != nil {
		return RestoreResult{}, err
	}
	tmp, err := os.MkdirTemp("", "sshmgr-restore-")
	if err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(tmp)
	tarPath := filepath.Join(tmp, "bundle.tar.gz")
	if err := b.cipher.Decrypt(bundlePath, tarPath, identityFile, passphrase); err != nil {
		return RestoreResult{}, err
	}
	extract := filepath.Join(tmp, "x")
	if err := extractTarGz(tarPath, extract); err != nil {
		return RestoreResult{}, fmt.Errorf("bundle is corrupt or not a valid archive - check the identity/recipient: %w", err)
	}
	return b.layDown(extract, fingerprintOf)
}

func (b *Bundler) layDown(extract string, fingerprintOf func(string) (string, error)) (RestoreResult, error) {
	res := RestoreResult{}
	sshRoot := filepath.Join(extract, "ssh")
	if fi, err := os.Stat(sshRoot); err == nil && fi.IsDir() {
		var paths []string
		_ = filepath.WalkDir(sshRoot, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				paths = append(paths, p)
			}
			return nil
		})
		sort.Strings(paths)
		for _, p := range paths {
			rel, _ := filepath.Rel(sshRoot, p)
			dest := filepath.Join(b.sshDir, rel)
			b2, err := os.ReadFile(p)
			if err != nil {
				return res, err
			}
			if err := writeBytesAtomic(dest, b2); err != nil {
				return res, err
			}
			res.Restored = append(res.Restored, filepath.ToSlash(rel))
			if strings.HasSuffix(dest, ".pub") {
				if fp, err := fingerprintOf(dest); err == nil {
					res.Fingerprints = append(res.Fingerprints, FP{Name: stem(filepath.Base(dest)), Fingerprint: fp})
				}
			}
		}
	}
	cfgRoot := filepath.Join(extract, "config")
	if entries, err := os.ReadDir(cfgRoot); err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			b2, err := os.ReadFile(filepath.Join(cfgRoot, n))
			if err != nil {
				return res, err
			}
			if err := writeBytesAtomic(filepath.Join(b.configDir, n), b2); err != nil {
				return res, err
			}
			res.Restored = append(res.Restored, "config/"+n)
		}
	}
	return res, nil
}

func verifyChecksum(bundlePath string) error {
	sidecar := bundlePath + ".sha256"
	data, err := os.ReadFile(sidecar)
	if err != nil {
		return nil // no sidecar -> nothing to verify
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return nil
	}
	want := parts[0]
	got, err := sha256File(bundlePath)
	if err != nil {
		return err
	}
	if want != got {
		return fmt.Errorf("bundle checksum mismatch: expected %s, got %s - refusing to restore", want, got)
	}
	return nil
}

func extractTarGz(tarball, destParent string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	cleanParent := filepath.Clean(destParent) + string(os.PathSeparator)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		dest := filepath.Join(destParent, filepath.FromSlash(hdr.Name))
		if !strings.HasPrefix(filepath.Clean(dest)+string(os.PathSeparator), cleanParent) {
			return fmt.Errorf("refusing path traversal in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode).Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

func writeBytesAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func stem(name string) string {
	if i := strings.LastIndex(name, "."); i > 0 {
		return name[:i]
	}
	return name
}
