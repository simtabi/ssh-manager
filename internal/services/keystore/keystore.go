// Package keystore generates and fingerprints SSH keys by shelling out to
// ssh-keygen, ported from services/keystore.py. Generation is non-destructive by
// default (an existing private key is never clobbered) and perms are set on create.
package keystore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/internal/util/perms"
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
// pair is removed first (callers MUST have snapshotted ~/.ssh). A hardware *-sk
// type falls back to its software equivalent when no FIDO2 device is present.
func (k *KeyStore) Generate(privPath, keyType, comment, passphrase string, overwrite bool) (GenResult, error) {
	if keyType == "" {
		keyType = "ed25519"
	}
	if exists(privPath) && !overwrite {
		fp, err := k.Fingerprint(privPath)
		if err != nil {
			return GenResult{}, err
		}
		return GenResult{Path: privPath, Fingerprint: fp, Created: false}, nil
	}
	if exists(privPath) { // overwrite: drop the old pair so ssh-keygen won't prompt
		_ = os.Remove(privPath)
		_ = os.Remove(pubPath(privPath))
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
	err := runKeygen(keyType, privPath, comment, passphrase)
	if err != nil && strings.HasSuffix(keyType, "-sk") {
		fallback := strings.TrimSuffix(keyType, "-sk") // ed25519-sk -> ed25519
		err = runKeygen(fallback, privPath, comment+" (sk-fallback)", passphrase)
	}
	if err != nil {
		return GenResult{}, fmt.Errorf("ssh-keygen failed: %w", err)
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

func runKeygen(keyType, privPath, comment, passphrase string) error {
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-f", privPath, "-C", comment, "-N", passphrase, "-q")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
