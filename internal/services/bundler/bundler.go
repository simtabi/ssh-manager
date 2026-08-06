// Package bundler makes and restores an age-encrypted backup. bundle tars
// {private keys + manifest + inventory + providers.json} (NEVER .env) and
// age-encrypts it with a SHA256 sidecar + a contents list; restore decrypts and
// lays the SAME keys back (same fingerprint). The cipher is behind a seam
// (Cipher) so tests inject a fake and the tar / lay-down / fingerprint guarantees
// are verifiable without age installed.
//
// Plaintext never touches the disk. The tar is piped straight into age and the
// decrypted stream is read into memory and written to its final destination, so
// there is no staging copy in $TMPDIR - which is world-traversable, often on a
// different filesystem, and outlives a crash.
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
	"path" // tar member names are always slash-separated
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

// Cipher transforms a stream. It is deliberately stream-shaped rather than
// file-shaped: a file-based cipher forces the caller to stage plaintext on disk.
type Cipher interface {
	Encrypt(dst io.Writer, src io.Reader, recipient string) error
	Decrypt(dst io.Writer, src io.Reader, identityFile string) error
}

// AgeCipher shells out to age (X25519 + ChaCha20-Poly1305) over stdin/stdout.
type AgeCipher struct{}

func (AgeCipher) Encrypt(dst io.Writer, src io.Reader, recipient string) error {
	return pipeThrough(dst, src, "-r", recipient)
}

func (AgeCipher) Decrypt(dst io.Writer, src io.Reader, identityFile string) error {
	args := []string{"-d"}
	if identityFile != "" {
		args = append(args, "-i", identityFile)
	}
	return pipeThrough(dst, src, args...)
}

func pipeThrough(dst io.Writer, src io.Reader, args ...string) error {
	if _, err := exec.LookPath("age"); err != nil {
		return fmt.Errorf("age not found: %s", ageHint)
	}
	cmd := exec.Command("age", args...)
	cmd.Stdin = src
	cmd.Stdout = dst
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("age: %s", msg)
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
// and writes the .sha256 + .contents sidecars. The tar is piped directly into the
// cipher, so the plaintext archive exists only in memory.
func (b *Bundler) Bundle(recipient, destDir, stamp string) (BundleResult, error) {
	if recipient == "" {
		return BundleResult{}, fmt.Errorf("no age recipient - set SSH_MANAGER_AGE_RECIPIENT or pass --recipient")
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return BundleResult{}, err
	}
	agePath := filepath.Join(destDir, "ssh-manager-"+stamp+".age")
	contents, err := b.encryptTo(agePath, recipient)
	if err != nil {
		_ = os.Remove(agePath) // never leave a half-written bundle to be trusted later
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

// encryptTo streams a fresh tar through the cipher into agePath, returning the
// member list. The two halves run concurrently over an io.Pipe, so nothing is
// buffered to disk in between.
func (b *Bundler) encryptTo(agePath, recipient string) ([]string, error) {
	// Owner-only from creation: the cipher must never be handed a descriptor to a
	// file that was briefly world-readable.
	out, err := os.OpenFile(agePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Close() }()

	type built struct {
		members []string
		err     error
	}
	pr, pw := io.Pipe()
	done := make(chan built, 1)
	go func() {
		members, err := b.writeTarGz(pw)
		// Closing with the error makes the cipher fail rather than encrypt and
		// sign a truncated archive that would look restorable.
		_ = pw.CloseWithError(err)
		done <- built{members, err}
	}()

	encErr := b.cipher.Encrypt(out, pr, recipient)
	// If the cipher died early the tar writer is still blocked on a write.
	_ = pr.CloseWithError(encErr)
	tar := <-done

	if tar.err != nil {
		return nil, tar.err // the upstream producer holds the root cause
	}
	if encErr != nil {
		return nil, encErr
	}
	return tar.members, out.Close()
}

func (b *Bundler) writeTarGz(w io.Writer) ([]string, error) {
	gz := gzip.NewWriter(w)
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
				closeAll(tw, gz)
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
				closeAll(tw, gz)
				return nil, err
			}
			members = append(members, arc)
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	return members, gz.Close()
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
	defer func() { _ = src.Close() }()
	_, err = io.Copy(tw, src)
	return err
}

func closeAll(tw *tar.Writer, gz *gzip.Writer) {
	_ = tw.Close()
	_ = gz.Close()
}

// Restore decrypts bundlePath and lays the same keys back down (verifying the
// SHA256 sidecar first). fingerprintOf fingerprints each restored .pub.
//
// The decrypted stream is read into memory and written straight to its final
// destination. Reading it whole before writing anything also means a corrupt or
// wrongly-keyed bundle is rejected before it has half-overwritten the tree.
func (b *Bundler) Restore(bundlePath, identityFile string, fingerprintOf func(string) (string, error)) (RestoreResult, error) {
	if _, err := os.Stat(bundlePath); err != nil {
		return RestoreResult{}, fmt.Errorf("bundle not found: %s", bundlePath)
	}
	if err := verifyChecksum(bundlePath); err != nil {
		return RestoreResult{}, err
	}
	members, err := b.decrypt(bundlePath, identityFile)
	if err != nil {
		return RestoreResult{}, err
	}
	return b.layDown(members, fingerprintOf)
}

// decrypt streams bundlePath through the cipher and returns the archive members.
func (b *Bundler) decrypt(bundlePath, identityFile string) ([]member, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := b.cipher.Decrypt(pw, f, identityFile)
		_ = pw.CloseWithError(err)
		done <- err
	}()

	members, readErr := readTarGz(pr)
	if readErr != nil {
		// The cipher is still writing into a pipe nobody will read again.
		_ = pr.CloseWithError(readErr)
	} else {
		// Drain any trailing bytes so the cipher can finish and exit.
		_, _ = io.Copy(io.Discard, pr)
	}
	if err := <-done; err != nil {
		return nil, err // a bad identity surfaces here, not as a corrupt archive
	}
	if readErr != nil {
		return nil, fmt.Errorf("bundle is corrupt or not a valid archive - check the identity/recipient: %w", readErr)
	}
	return members, nil
}

func (b *Bundler) layDown(members []member, fingerprintOf func(string) (string, error)) (RestoreResult, error) {
	res := RestoreResult{}
	sorted := append([]member(nil), members...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, m := range sorted {
		var dest, label string
		switch {
		case strings.HasPrefix(m.name, sshPrefix):
			rel := strings.TrimPrefix(m.name, sshPrefix)
			dest = filepath.Join(b.sshDir, filepath.FromSlash(rel))
			if !within(b.sshDir, dest) {
				return res, fmt.Errorf("refusing path traversal in bundle: %s", m.name)
			}
			label = rel
		case strings.HasPrefix(m.name, configPrefix):
			// Flat by construction, and pinning the base name keeps a crafted
			// member from escaping the config dir.
			name := path.Base(m.name)
			dest = filepath.Join(b.configDir, name)
			label = configPrefix + name
		default:
			// A bundle only ever holds those two roots. Anything else means the
			// archive was tampered with - including a traversal like
			// "ssh/../../x", which path.Clean has already stripped the prefix
			// from. Refusing beats silently skipping part of a restore.
			return res, fmt.Errorf("refusing unexpected member in bundle: %s", m.name)
		}
		if err := writeBytesAtomic(dest, m.data); err != nil {
			return res, err
		}
		res.Restored = append(res.Restored, label)
		if strings.HasSuffix(dest, ".pub") {
			if fp, err := fingerprintOf(dest); err == nil {
				res.Fingerprints = append(res.Fingerprints, FP{Name: stem(filepath.Base(dest)), Fingerprint: fp})
			}
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

// member is one decrypted archive entry, held in memory rather than staged on
// disk. Bundles are keys and small JSON models, so the whole thing fits easily.
type member struct {
	name string
	data []byte
}

// maxBundleBytes bounds what a bundle can expand to, so a malicious or corrupt
// archive cannot exhaust memory during the read-it-all-first step.
const maxBundleBytes = 64 << 20

func readTarGz(r io.Reader) ([]member, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(io.LimitReader(gz, maxBundleBytes))
	var members []member
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return members, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: path.Clean(hdr.Name), data: data})
	}
}

// within reports whether dest stays inside root, so a crafted member name cannot
// write outside the tree it claims to belong to.
func within(root, dest string) bool {
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
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
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
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
	defer func() { _ = f.Close() }()
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
