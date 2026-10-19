// Package validate checks that managed keypairs parse, that the public key
// matches the private key, and that perms are correct. Ported from
// facade.validate_keys + _validate_one. Read-only: it never mutates ~/.ssh.
package validate

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/opstore"
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
	op     *opstore.Client
}

// New builds a validate service over the given manifest and ~/.ssh directory.
func New(m *manifest.Manifest, sshDir string) *Service {
	return &Service{m: m, sshDir: sshDir, ks: keystore.New(), op: opstore.New()}
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
		priv := s.m.KeyPath(s.sshDir, ref)
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

	inOP := s.m.Profiles[profile].InOnePassword()
	switch {
	case inOP && exists(priv):
		// ssh is pointed at the .pub and the 1Password agent; a private key file
		// here is not what it offers, and is usually the key from before the
		// profile moved to 1Password.
		issues = append(issues, "a private key file is on disk, but this profile keeps its keys in "+
			"1Password - ssh will not use it. Run `sshmgr rotate "+profile+"/"+keyName+
			"` to generate the key in 1Password")
	case inOP:
		// expected: the private key is in 1Password
	case !exists(priv):
		issues = append(issues, "private key missing")
	case !perms.PermsOK(priv, perms.PrivateKeyMode):
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

	if inOP {
		i, n := s.checkOnePassword(profile, keyName, pubText)
		issues, notes = append(issues, i...), append(notes, n...)
	}

	// Real pair check: derive the public key from the private material.
	if !inOP && exists(priv) {
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

// checkOnePassword confirms the key's item is in the profile's vault and that
// its public key is the one on disk - the pair check for a key whose private
// half never leaves 1Password.
func (s *Service) checkOnePassword(profile, keyName, pubText string) (issues, notes []string) {
	vault := s.m.Profiles[profile].OPVault
	if err := s.op.Available(); err != nil {
		return nil, []string{"1Password item not checked: " + err.Error()}
	}
	it, err := s.op.Get(vault, keyName)
	switch {
	case errors.Is(err, opstore.ErrNotFound):
		return []string{fmt.Sprintf("no item %q in 1Password vault %q - run `sshmgr reconcile` "+
			"to create it", keyName, vault)}, nil
	case err != nil:
		return nil, []string{"1Password item not checked: " + err.Error()}
	}
	if pubText != "" && authkeys.KeyBody(it.PublicKey) != authkeys.KeyBody(pubText) {
		issues = append(issues, fmt.Sprintf("the .pub does NOT match 1Password item %q in vault %q",
			keyName, vault))
	}
	return issues, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
