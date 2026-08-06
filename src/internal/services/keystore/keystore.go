// Package keystore generates and fingerprints SSH keys by shelling out to
// ssh-keygen. Generation is non-destructive by
// default (an existing private key is never clobbered) and perms are set on create.
package keystore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/askpass"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
)

const installHint = "install OpenSSH (macOS ships it; else: brew install openssh)"

// GenResult is the outcome of Generate. Created is false when the key already
// existed (an idempotent re-run).
type GenResult struct {
	Path        string
	Fingerprint string
	Created     bool
}

// KeyStore mints and inspects keys.
type KeyStore struct{}

// New returns a KeyStore.
func New() *KeyStore { return &KeyStore{} }

// pubPath is the public-key path ssh-keygen writes: the private path with ".pub"
// appended (ssh-keygen appends literally, so this matches what is on disk).
func pubPath(priv string) string { return priv + ".pub" }

func requireKeygen() error {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return fmt.Errorf("ssh-keygen not found: %s", installHint)
	}
	return nil
}

// Generate mints a keypair at privPath. Idempotent and non-destructive by default
// (an existing key is kept and its fingerprint returned); with overwrite the old
// pair is replaced (callers MUST have snapshotted ~/.ssh). A hardware *-sk
// type falls back to its software equivalent when no FIDO2 device is present.
func (k *KeyStore) Generate(privPath, keyType, comment, passphrase string, overwrite bool) (GenResult, error) {
	if keyType == "" {
		keyType = "ed25519"
	}
	if err := refuseSymlink(privPath); err != nil {
		return GenResult{}, err
	}
	if err := refuseSymlink(pubPath(privPath)); err != nil {
		return GenResult{}, err
	}
	if exists(privPath) && !overwrite {
		fp, err := k.Fingerprint(privPath)
		if err != nil {
			return GenResult{}, err
		}
		return GenResult{Path: privPath, Fingerprint: fp, Created: false}, nil
	}
	if err := requireKeygen(); err != nil {
		return GenResult{}, err
	}
	parent := filepath.Dir(privPath)
	if err := os.MkdirAll(parent, perms.DirMode); err != nil {
		return GenResult{}, err
	}
	if err := perms.SetPerms(parent, perms.DirMode); err != nil {
		return GenResult{}, err
	}

	staged, cleanup, err := mint(parent, keyType, comment, passphrase)
	defer cleanup()
	if err != nil {
		return GenResult{}, err
	}
	// The old pair is only displaced once a replacement exists, so a failed mint
	// cannot leave the profile without a key.
	if overwrite {
		if err := archivePredecessor(privPath); err != nil {
			return GenResult{}, err
		}
	}
	if err := os.Rename(staged, privPath); err != nil {
		return GenResult{}, err
	}
	if err := os.Rename(pubPath(staged), pubPath(privPath)); err != nil {
		return GenResult{}, err
	}
	if err := perms.SetPerms(privPath, perms.PrivateKeyMode); err != nil {
		return GenResult{}, err
	}
	if err := perms.SetPerms(pubPath(privPath), perms.PublicKeyMode); err != nil {
		return GenResult{}, err
	}
	fp, err := k.Fingerprint(privPath)
	if err != nil {
		return GenResult{}, err
	}
	return GenResult{Path: privPath, Fingerprint: fp, Created: true}, nil
}

// mint generates a pair inside a directory created for this call, and returns the
// staged private key path plus a cleanup func the caller must defer.
//
// Generating straight to the final path would let ssh-keygen write private key
// material through a symlink planted there by someone else, and would leave the
// key readable for however long it took to chmod it afterwards. A directory that
// did not exist a moment ago can contain neither.
func mint(parent, keyType, comment, passphrase string) (string, func(), error) {
	dir, err := os.MkdirTemp(parent, ".mint-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := perms.SetPerms(dir, perms.DirMode); err != nil {
		return "", cleanup, err
	}
	staged := filepath.Join(dir, "key")

	err = runKeygen(keyType, staged, comment, passphrase)
	if err != nil && strings.HasSuffix(keyType, "-sk") {
		// No FIDO2 authenticator present. ssh-keygen refuses to overwrite, so the
		// partial attempt has to go before the software fallback is tried.
		_ = os.Remove(staged)
		_ = os.Remove(pubPath(staged))
		fallback := strings.TrimSuffix(keyType, "-sk") // ed25519-sk -> ed25519
		err = runKeygen(fallback, staged, comment+" (sk-fallback)", passphrase)
	}
	if err != nil {
		return "", cleanup, fmt.Errorf("ssh-keygen failed: %w", err)
	}
	return staged, cleanup, nil
}

func runKeygen(keyType, privPath, comment, passphrase string) error {
	args := []string{"-t", keyType, "-f", privPath, "-C", comment, "-q"}
	if passphrase == "" {
		// An empty passphrase is not a secret, and -N keeps the run silent.
		args = append(args, "-N", "")
	}
	cmd := exec.Command("ssh-keygen", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if passphrase != "" {
		// Never -N a real passphrase: argv is world-readable via ps. Hand it over
		// through the askpass protocol instead, and also offer it on stdin, which
		// is what pre-8.4 ssh-keygen reads when it has no terminal to prompt on.
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot locate own binary to act as askpass helper: %w", err)
		}
		cmd.Env = askpass.Environ(self, passphrase)
		cmd.Stdin = strings.NewReader(passphrase + "\n" + passphrase + "\n")
	}

	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

// Fingerprint returns the SHA256:... fingerprint of a public or private key.
func (k *KeyStore) Fingerprint(path string) (string, error) {
	if err := requireKeygen(); err != nil {
		return "", err
	}
	out, err := exec.Command("ssh-keygen", "-lf", path).Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen -lf failed for %s: %w", path, err)
	}
	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "SHA256:") {
		return "", fmt.Errorf("could not parse fingerprint from: %q", strings.TrimSpace(string(out)))
	}
	return parts[1], nil
}

// PublicFromPrivate derives the public key from the private key material
// (ssh-keygen -y) - the only way to prove a keypair matches. It returns the public
// line (empty if it could not be derived) and whether the key is encrypted: empty
// + encrypted=true means a valid passphrase-protected key, empty + encrypted=false
// means an invalid/unreadable private key. err is non-nil only if ssh-keygen is
// absent.
func (k *KeyStore) PublicFromPrivate(privPath string) (pub string, encrypted bool, err error) {
	if err := requireKeygen(); err != nil {
		return "", false, err
	}
	// -P "" supplies an empty passphrase: succeeds for unencrypted keys, fails
	// cleanly (no prompt/hang) for encrypted ones.
	out, runErr := exec.Command("ssh-keygen", "-y", "-P", "", "-f", privPath).Output()
	if runErr == nil {
		if line := strings.TrimSpace(string(out)); line != "" {
			return line, false, nil
		}
	}
	// Distinguish "encrypted" from "invalid" by inspecting the file itself, not a
	// locale-sensitive stderr string - a real key file has a PRIVATE KEY header.
	head, rerr := os.ReadFile(privPath)
	if rerr != nil {
		return "", false, nil
	}
	return "", strings.Contains(string(head), "PRIVATE KEY-----"), nil
}

// archivePredecessor moves the key being replaced into the profile's old/ dir,
// the same place rotation parks a superseded key, keeping the one-predecessor
// invariant.
//
// Overwriting used to just unlink the pair and lean on the pre-mutation snapshot
// to make that reversible. Snapshots no longer carry private keys, so without
// this an overwrite would be unrecoverable.
func archivePredecessor(privPath string) error {
	if !exists(privPath) {
		return nil
	}
	oldDir := filepath.Join(filepath.Dir(privPath), "old")
	if err := os.MkdirAll(oldDir, perms.DirMode); err != nil {
		return err
	}
	if err := perms.SetPerms(oldDir, perms.DirMode); err != nil {
		return err
	}
	name := filepath.Base(privPath)
	for _, m := range []struct{ from, to string }{
		{privPath, filepath.Join(oldDir, name)},
		{pubPath(privPath), pubPath(filepath.Join(oldDir, name))},
	} {
		if !exists(m.from) {
			continue
		}
		_ = os.Remove(m.to) // at most one predecessor is kept
		if err := os.Rename(m.from, m.to); err != nil {
			return fmt.Errorf("could not archive the key being replaced: %w", err)
		}
	}
	return nil
}

// exists reports whether a path exists, without following symlinks: a symlink
// sitting at a key path is something to notice, not something to write through.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// refuseSymlink rejects a key path that is a symlink, which would otherwise
// place private key material wherever the link points.
func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	return fmt.Errorf("%s is a symlink; refusing to write key material through it", path)
}
