package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keystore"
	"github.com/simtabi/ssh-manager/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/internal/services/knownhosts"
)

const showManifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "keys": [{"name": "work_spare-ed25519"}],
      "hosts": [{"alias": "gh-work", "hostname": "github.com", "user": "git",
                 "key_name": "work_gh-ed25519", "port": 443}]}
  }
}`

type showFixture struct {
	m    *manifest.Manifest
	keys *keysvc.Service
	kh   *knownhosts.Service
	ssh  string
	priv string
}

func newShowFixture(t *testing.T) showFixture {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(showManifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	dir := filepath.Join(ssh, "profiles", "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dir, "work_gh-ed25519")
	if _, err := keystore.New().Generate(priv, "ed25519", "work/gh-work", "", false); err != nil {
		t.Fatal(err)
	}

	inv := inventory.New()
	created, expires := "2026-01-01", "2027-01-01"
	fp, err := keystore.New().Fingerprint(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	inv.Record(fp, inventory.KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519",
		Created: &created, ExpiresOn: &expires, RotateAfterDays: 365,
		Deployments: []inventory.Deployment{{Target: "gh-work", Method: "manual", Verified: true}},
	})
	kh := knownhosts.New(ssh)
	if _, err := kh.Add([]string{"[github.com]:443 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"}); err != nil {
		t.Fatal(err)
	}
	return showFixture{m: &m, keys: keysvc.New(&m, inv, ssh), kh: kh, ssh: ssh, priv: priv}
}

// The one thing show must never do. It reports files by path, mode and
// fingerprint precisely so that reading it aloud, pasting it into an issue, or
// piping it somewhere cannot disclose a key.
func TestShowNeverPrintsKeyMaterial(t *testing.T) {
	f := newShowFixture(t)
	body, err := os.ReadFile(f.priv)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	host := f.m.Profiles["work"].Hosts[0]
	if err := showHost(&out, f.m, f.keys, f.kh, "work", host); err != nil {
		t.Fatal(err)
	}
	if err := showProfile(&out, f.m, f.keys, f.kh, "work", f.m.Profiles["work"]); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "PRIVATE KEY") {
		t.Error("show printed a private key header")
	}
	// Every non-trivial line of the real private key, base64 body included.
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if len(line) < 20 {
			continue
		}
		if strings.Contains(got, line) {
			t.Fatalf("show printed private key material: %.20s...", line)
		}
	}
}

func TestShowHostReportsConfigKeyAndPins(t *testing.T) {
	f := newShowFixture(t)
	var out bytes.Buffer
	if err := showHost(&out, f.m, f.keys, f.kh, "work", f.m.Profiles["work"].Hosts[0]); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		// The rendered block, as the manifest would produce it.
		"Host gh-work", "HostName github.com", "Port 443",
		"IdentityFile ~/.ssh/profiles/work/work_gh-ed25519",
		"IdentitiesOnly yes", "UserKnownHostsFile ~/.ssh/known_hosts",
		// The key: paths and modes, deployment, expiry.
		"work/work_gh-ed25519", "(0600)", "(0644)", "expires on:   2027-01-01",
		"gh-work via manual (verified)",
		// The pin, decoded out of a hashed store, and attributed.
		"[github.com]:443", "ssh-ed25519", "hashed", "sshmgr",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("show output missing %q:\n%s", want, got)
		}
	}
}

// The trust store is hashed, so a host's pin cannot be found by grepping it -
// which is exactly why show has to decode it.
func TestShowReportsAnUnpinnedHost(t *testing.T) {
	f := newShowFixture(t)
	if err := os.Remove(f.kh.Path()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := showHost(&out, f.m, f.keys, f.kh, "work", f.m.Profiles["work"].Hosts[0]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not pinned") ||
		!strings.Contains(out.String(), "knownhosts pin gh-work") {
		t.Errorf("an unpinned host should say so and offer the fix:\n%s", out.String())
	}
}

func TestShowProfileFlagsAnUnwiredKey(t *testing.T) {
	f := newShowFixture(t)
	var out bytes.Buffer
	if err := showProfile(&out, f.m, f.keys, f.kh, "work", f.m.Profiles["work"]); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "work/work_spare-ed25519") {
		t.Errorf("a declared key should be listed even with no host:\n%s", got)
	}
	if !strings.Contains(got, "UNWIRED") || !strings.Contains(got, keysvc.Missing) {
		t.Errorf("an unwired, unminted key should be called out:\n%s", got)
	}
}

// A key regenerated outside sshmgr leaves the inventory describing a key that is
// no longer on disk; deployments and expiry then refer to nothing.
func TestShowFlagsAFingerprintMismatch(t *testing.T) {
	f := newShowFixture(t)
	if err := os.Remove(f.priv); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.priv + ".pub"); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.New().Generate(f.priv, "ed25519", "regenerated by hand", "", false); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := showKey(&out, f.keys, manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"}, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "MISMATCH") {
		t.Errorf("a key replaced behind sshmgr's back should be flagged:\n%s", out.String())
	}
}
