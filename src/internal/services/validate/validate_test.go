package validate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
)

const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [
      {"alias": "good", "hostname": "h1", "user": "u"},
      {"alias": "missing", "hostname": "h2", "user": "u"},
      {"alias": "badperms", "hostname": "h3", "user": "u"},
      {"alias": "mismatch", "hostname": "h4", "user": "u"},
      {"alias": "malformed", "hostname": "h5", "user": "u"}
    ]}
  }
}`

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func keyPath(t *testing.T, m *manifest.Manifest, ssh, alias string) string {
	t.Helper()
	for _, h := range m.Profiles["work"].Hosts {
		if h.Alias == alias {
			k, err := m.ResolvedKeyName("work", h)
			if err != nil {
				t.Fatal(err)
			}
			return filepath.Join(ssh, "profiles", "work", k)
		}
	}
	t.Fatalf("alias %q not found", alias)
	return ""
}

func TestValidateKeys(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	ssh := t.TempDir()
	ks := keystore.New()

	// Mint a valid pair for every host.
	for _, alias := range []string{"good", "missing", "badperms", "mismatch", "malformed"} {
		if _, err := ks.Generate(keyPath(t, m, ssh, alias), "ed25519", alias, "", false); err != nil {
			t.Fatal(err)
		}
	}
	// Introduce defects.
	_ = os.Remove(keyPath(t, m, ssh, "missing"))          // private key gone
	_ = os.Remove(keyPath(t, m, ssh, "missing") + ".pub") // and its pub
	if runtime.GOOS != "windows" {                        // perms are POSIX-only
		if err := os.Chmod(keyPath(t, m, ssh, "badperms"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Swap mismatch's .pub for a different valid public key.
	other := filepath.Join(t.TempDir(), "other")
	if _, err := ks.Generate(other, "ed25519", "x", "", false); err != nil {
		t.Fatal(err)
	}
	otherPub, _ := os.ReadFile(other + ".pub")
	_ = os.WriteFile(keyPath(t, m, ssh, "mismatch")+".pub", otherPub, 0o644)
	// Corrupt malformed's .pub.
	_ = os.WriteFile(keyPath(t, m, ssh, "malformed")+".pub", []byte("not a key\n"), 0o644)

	checks, err := New(m, ssh).ValidateKeys("")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]KeyCheck{}
	for _, c := range checks {
		byName[aliasOf(t, m, c.KeyName)] = c
	}

	if c := byName["good"]; !c.OK || c.Fingerprint == nil {
		t.Errorf("good: ok=%v fp=%v issues=%v", c.OK, c.Fingerprint, c.Issues)
	}
	if c := byName["missing"]; c.OK || !hasIssue(c, "private key missing") || !hasIssue(c, "public key (.pub) missing") {
		t.Errorf("missing: %+v", c)
	}
	if runtime.GOOS != "windows" {
		if c := byName["badperms"]; c.OK || !hasIssue(c, "private key perms not 600") {
			t.Errorf("badperms: %+v", c)
		}
	}
	if c := byName["mismatch"]; c.OK || !hasIssue(c, "public key does NOT match the private key") {
		t.Errorf("mismatch: %+v", c)
	}
	if c := byName["malformed"]; c.OK || !hasIssue(c, "public key is malformed") {
		t.Errorf("malformed: %+v", c)
	}
}

func TestSelectorFilterAndUnknown(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	ssh := t.TempDir()
	svc := New(m, ssh)

	// Profile selector -> all five keys (all missing, but present in the result).
	checks, err := svc.ValidateKeys("work")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 5 {
		t.Errorf("profile selector: got %d checks want 5", len(checks))
	}
	// Unknown selector -> error.
	if _, err := svc.ValidateKeys("nope"); err == nil {
		t.Error("unknown selector should error")
	}
}

func hasIssue(c KeyCheck, want string) bool {
	for _, i := range c.Issues {
		if i == want {
			return true
		}
	}
	return false
}

func aliasOf(t *testing.T, m *manifest.Manifest, keyName string) string {
	t.Helper()
	for _, h := range m.Profiles["work"].Hosts {
		k, _ := m.ResolvedKeyName("work", h)
		if k == keyName {
			return h.Alias
		}
	}
	return keyName
}

// A passphrase-protected key is the recommended configuration, so it must not
// read as a defect. The pair cannot be checked without the passphrase, which is
// a note - "not verified" - rather than an issue, and the key stays OK. Treating
// it as broken would put a red line against the most secure setup the tool
// supports, on every run.
func TestAnEncryptedKeyIsNotedNotFailed(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	m := loadManifest(t)
	ssh := t.TempDir()
	priv := keyPath(t, m, ssh, "good")
	if _, err := keystore.New().Generate(priv, "ed25519", "good", "", false); err != nil {
		t.Fatal(err)
	}
	// Encrypted in place with a direct ssh-keygen call rather than through
	// keystore.Generate: that path hands the passphrase over via SSH_ASKPASS
	// pointing at os.Executable(), which inside a test binary is the test binary,
	// so it would hang waiting for a helper that never answers. The askpass
	// protocol itself is covered in internal/util/askpass.
	out, err := exec.Command("ssh-keygen", "-p", "-f", priv, "-P", "", "-N", "test-passphrase").CombinedOutput()
	if err != nil {
		t.Fatalf("could not encrypt the test key: %v: %s", err, out)
	}

	checks, err := New(m, ssh).ValidateKeys("work_good-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(checks))
	}
	c := checks[0]
	if !c.OK {
		t.Errorf("an encrypted key should be OK, got issues %v", c.Issues)
	}
	if len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "encrypted") {
		t.Errorf("notes = %v, want the unverifiable pair recorded as a note", c.Notes)
	}
	for _, issue := range c.Issues {
		if strings.Contains(issue, "unreadable") || strings.Contains(issue, "does NOT match") {
			t.Errorf("encrypted key misreported as broken: %q", issue)
		}
	}
}

// One person under two orgs uses the same key file name in both. A bare name
// selector has to validate every profile that has it: checking only the first
// reports "1 key, OK" while a broken key with the same name sits unchecked in
// another profile.
const sharedNameJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "personal": {"key_scope": "per_service", "hosts": [
      {"alias": "gh-personal", "hostname": "github.com", "user": "git", "key_name": "imani_github-ed25519"}]},
    "adelsaiq": {"key_scope": "per_service", "hosts": [
      {"alias": "gh-adelsaiq", "hostname": "gitlab.com", "user": "git", "key_name": "imani_github-ed25519"}]}
  }
}`

func TestABareNameValidatesEveryProfileThatHasIt(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(sharedNameJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	ks := keystore.New()
	for _, profile := range []string{"personal", "adelsaiq"} {
		if _, err := ks.Generate(filepath.Join(ssh, "profiles", profile, "imani_github-ed25519"),
			"ed25519", profile, "", false); err != nil {
			t.Fatal(err)
		}
	}
	// Break only adelsaiq's copy.
	if err := os.WriteFile(filepath.Join(ssh, "profiles", "adelsaiq", "imani_github-ed25519.pub"),
		[]byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := New(&m, ssh)

	checks, err := svc.ValidateKeys("imani_github-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 2 {
		t.Fatalf("a bare name matched %d keys, want both profiles' copies", len(checks))
	}
	byProfile := map[string]KeyCheck{}
	for _, c := range checks {
		byProfile[c.Profile] = c
	}
	if !byProfile["personal"].OK {
		t.Errorf("personal's copy is intact: %+v", byProfile["personal"])
	}
	if byProfile["adelsaiq"].OK {
		t.Error("the broken copy was reported clean")
	}

	// The composite form narrows to exactly one, which is how a user asks about
	// the copy they mean when the name alone is ambiguous.
	one, err := svc.ValidateKeys("adelsaiq/imani_github-ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Profile != "adelsaiq" {
		t.Errorf("profile/key selector = %+v, want adelsaiq's copy alone", one)
	}
}

// A key a profile declares that no host references still has files on disk, so
// it still has perms and a pair to check. Walking resolved hosts instead of
// KeyRefs would skip it - and an unwired key is exactly the one nobody notices
// has rotted.
func TestADeclaredButUnwiredKeyIsStillChecked(t *testing.T) {
	const j = `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "vault":{"key_scope":"per_service","keys":[{"name":"vault_backup-ed25519"}],"hosts":[]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	checks, err := New(&m, t.TempDir()).ValidateKeys("")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].KeyName != "vault_backup-ed25519" {
		t.Fatalf("checks = %+v, want the declared key", checks)
	}
	if checks[0].OK || !hasIssue(checks[0], "private key missing") {
		t.Errorf("an unminted declared key should report as missing: %+v", checks[0])
	}
}
