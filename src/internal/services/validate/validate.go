// Package validate checks that managed keypairs parse, that the public key
// matches the private key, and that perms are correct. Ported from
// facade.validate_keys + _validate_one. Read-only: it never mutates ~/.ssh.
package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/perms"
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

// ValidateKeys validates every managed key, one check per profile+name pair.
// selector filters by profile, key name, or the composite "profile/key" form
// (empty means all); an unmatched selector is an error. A bare key name used by
// several profiles validates every one of them - checking only the first would
// report a broken key as clean.
func (s *Service) ValidateKeys(selector string) ([]KeyCheck, error) {
	// KeyRefs, not IterResolved: it is already one entry per profile+name, and it
	// covers a key its profile declares that no host uses - which still has files
	// on disk to check.
	refs, err := s.m.KeyRefs()
	if err != nil {
		return nil, err
	}
	var checks []KeyCheck
	for _, ref := range refs {
		if !selectorMatches(selector, ref) {
			continue
		}
		priv := filepath.Join(s.sshDir, "profiles", ref.Profile, ref.KeyName)
		checks = append(checks, s.validateOne(ref.Profile, ref.KeyName, priv))
	}
	if len(checks) == 0 && selector != "" {
		return nil, fmt.Errorf("unknown key or profile: %q", selector)
	}
	return checks, nil
}

func selectorMatches(selector string, ref manifest.KeyRef) bool {
	return selector == "" || selector == ref.Profile ||
		selector == ref.KeyName || selector == ref.String()
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
