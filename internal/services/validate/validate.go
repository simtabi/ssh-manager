// Package validate checks that managed keypairs parse, that the public key
// matches the private key, and that perms are correct. Ported from
// facade.validate_keys + _validate_one. Read-only: it never mutates ~/.ssh.
package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/util/perms"
)

// KeyCheck is the validation result for one managed key.
type KeyCheck struct {
	KeyName     string
	Profile     string
	Fingerprint *string
	OK          bool
	Issues      []string
	Notes       []string
}

// Service validates the manifest's managed keys against ~/.ssh.
type Service struct {
	m      *manifest.Manifest
	sshDir string
	ks     *keystore.KeyStore
}

// New builds a validate service over the given manifest and ~/.ssh directory.
func New(m *manifest.Manifest, sshDir string) *Service {
	return &Service{m: m, sshDir: sshDir, ks: keystore.New()}
}

// ValidateKeys validates every managed key, deduped by key name. selector filters
// by key name or profile (empty means all); an unmatched selector is an error.
func (s *Service) ValidateKeys(selector string) ([]KeyCheck, error) {
	resolved, err := s.m.IterResolved()
	if err != nil {
		return nil, err
	}
	if selector != "" {
		matched := false
		for _, rk := range resolved {
			if selector == rk.KeyName || selector == rk.Profile {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("unknown key or profile: %q", selector)
		}
	}
	seen := map[string]bool{}
	var checks []KeyCheck
	for _, rk := range resolved {
		if seen[rk.KeyName] {
			continue
		}
		if selector != "" && selector != rk.KeyName && selector != rk.Profile {
			continue
		}
		seen[rk.KeyName] = true
		priv := filepath.Join(s.sshDir, "profiles", rk.Profile, rk.KeyName)
		checks = append(checks, s.validateOne(rk.Profile, rk.KeyName, priv))
	}
	return checks, nil
}

func (s *Service) validateOne(profile, keyName, priv string) KeyCheck {
	pub := priv + ".pub"
	var issues, notes []string
	var fp *string
	pubText := ""

	if !exists(priv) {
		issues = append(issues, "private key missing")
	} else if !perms.PermsOK(priv, perms.PrivateKeyMode) {
		issues = append(issues, "private key perms not 600")
	}

	if !exists(pub) {
		issues = append(issues, "public key (.pub) missing")
	} else {
		b, _ := os.ReadFile(pub)
		pubText = strings.TrimSpace(string(b))
		if !authkeys.IsValidPublicKey(pubText) {
			issues = append(issues, "public key is malformed")
		} else if f, err := s.ks.Fingerprint(pub); err == nil {
			fp = &f
		}
		if !perms.PermsOK(pub, perms.PublicKeyMode) {
			issues = append(issues, "public key perms not 644")
		}
	}

	// Real pair check: derive the public key from the private material.
	if exists(priv) {
		derived, encrypted, _ := s.ks.PublicFromPrivate(priv)
		switch {
		case derived != "":
			if pubText != "" && authkeys.KeyBody(derived) != authkeys.KeyBody(pubText) {
				issues = append(issues, "public key does NOT match the private key")
			}
		case encrypted:
			notes = append(notes, "encrypted - pair not verified without passphrase")
		default:
			issues = append(issues, "private key unreadable / not a valid key")
		}
	}

	return KeyCheck{
		KeyName: keyName, Profile: profile, Fingerprint: fp,
		OK: len(issues) == 0, Issues: issues, Notes: notes,
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
