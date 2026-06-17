package validate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
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
	os.Remove(keyPath(t, m, ssh, "missing"))          // private key gone
	os.Remove(keyPath(t, m, ssh, "missing") + ".pub") // and its pub
	if runtime.GOOS != "windows" {                    // perms are POSIX-only
		os.Chmod(keyPath(t, m, ssh, "badperms"), 0o644)
	}
	// Swap mismatch's .pub for a different valid public key.
	other := filepath.Join(t.TempDir(), "other")
	if _, err := ks.Generate(other, "ed25519", "x", "", false); err != nil {
		t.Fatal(err)
	}
	otherPub, _ := os.ReadFile(other + ".pub")
	os.WriteFile(keyPath(t, m, ssh, "mismatch")+".pub", otherPub, 0o644)
	// Corrupt malformed's .pub.
	os.WriteFile(keyPath(t, m, ssh, "malformed")+".pub", []byte("not a key\n"), 0o644)

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
