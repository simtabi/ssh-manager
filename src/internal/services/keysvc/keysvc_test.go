package keysvc

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/query"
)

// work/work_gh-ed25519  - wired to a host, on disk, recorded, deployed
// work/work_spare-rsa   - declared only, on disk, no inventory record
// vault/vault_cold-ed25519 - declared only, nothing on disk
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "work": {"key_scope": "per_service",
      "keys": [{"name": "work_spare-rsa", "type": "rsa", "rotate_after_days": 30}],
      "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git"}]},
    "vault": {"key_scope": "per_service",
      "keys": [{"name": "vault_cold-ed25519"}],
      "hosts": []}
  }
}`

func fixture(t *testing.T) *Service {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	write := func(profile, name, body string, mode os.FileMode) {
		dir := filepath.Join(ssh, "profiles", profile)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("work", "work_gh-ed25519", "PRIVATE\n", 0o600)
	write("work", "work_gh-ed25519.pub", "ssh-ed25519 AAAA gh\n", 0o644)
	write("work", "work_spare-rsa", "PRIVATE\n", 0o600)
	write("work", "work_spare-rsa.pub", "ssh-rsa AAAA spare\n", 0o644)

	inv := inventory.New()
	created, expires := "2026-01-01", "2027-01-01"
	inv.Record("SHA256:gh", inventory.KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519",
		Created: &created, ExpiresOn: &expires, RotateAfterDays: 365,
		Deployments: []inventory.Deployment{{Target: "gh", Method: "manual", Verified: true}},
	})
	return New(&m, inv, ssh)
}

func rowsByRef(t *testing.T, s *Service, selector string) map[string]Row {
	t.Helper()
	rows, err := s.Rows(selector)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Row{}
	for _, r := range rows {
		out[r.Ref.String()] = r
	}
	return out
}

func TestRowsCoverDeclaredAndHostDerivedKeys(t *testing.T) {
	s := fixture(t)
	rows, err := s.Rows("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"work/work_gh-ed25519", "work/work_spare-rsa", "vault/vault_cold-ed25519"}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		if got := rows[i].Ref.String(); got != w {
			t.Errorf("rows[%d] = %s, want %s", i, got, w)
		}
	}

	byRef := rowsByRef(t, s, "")
	gh := byRef["work/work_gh-ed25519"]
	if !gh.Wired() || gh.Hosts[0] != "gh" {
		t.Errorf("gh key should be wired to host gh: %+v", gh.Hosts)
	}
	if gh.Declared {
		t.Error("a key only a host names is not declared")
	}
	if gh.Status != query.Deployed || gh.Fingerprint != "SHA256:gh" || gh.ExpiresOn != "2027-01-01" {
		t.Errorf("inventory not joined onto the row: %+v", gh)
	}
	if !gh.PrivateOnDisk || !gh.PublicOnDisk || !gh.Recorded {
		t.Errorf("a present, recorded pair should report as such: %+v", gh)
	}
}

func TestRowsResolveTypeAndRotationOverrides(t *testing.T) {
	byRef := rowsByRef(t, fixture(t), "")
	spare := byRef["work/work_spare-rsa"]
	if spare.Type != "rsa" || spare.RotateAfterDays != 30 {
		t.Errorf("declared overrides not resolved: type=%q rotate=%d", spare.Type, spare.RotateAfterDays)
	}
	cold := byRef["vault/vault_cold-ed25519"]
	if cold.Type != "ed25519" || cold.RotateAfterDays != 365 {
		t.Errorf("defaults not inherited: type=%q rotate=%d", cold.Type, cold.RotateAfterDays)
	}
}

func TestSelectorFiltersAndRejectsTypos(t *testing.T) {
	s := fixture(t)
	for selector, want := range map[string]int{
		"work":                   2, // profile
		"vault":                  1,
		"gh":                     1, // host alias
		"work_spare-rsa":         1, // bare key name
		"work/work_spare-rsa":    1, // composite
		"vault/vault_cold-ed255": 0, // typo -> error, checked below
	} {
		rows, err := s.Rows(selector)
		if want == 0 {
			if err == nil {
				t.Errorf("selector %q should have errored, got %d rows", selector, len(rows))
			}
			continue
		}
		if err != nil {
			t.Errorf("selector %q: %v", selector, err)
			continue
		}
		if len(rows) != want {
			t.Errorf("selector %q matched %d rows, want %d", selector, len(rows), want)
		}
	}
}

// mintPair writes a real keypair, which Detail needs: it fingerprints the .pub
// with ssh-keygen rather than trusting what the inventory says.
func mintPair(t *testing.T, path, comment string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	fp, err := keystore.New().Fingerprint(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// Detail exists to answer the one question a Row cannot: is the key on disk
// still the key the inventory is describing? A key regenerated outside sshmgr -
// a bare ssh-keygen over the same path, a restore from somewhere else - leaves
// the record's deployments and expiry describing a key that is gone, while every
// listing still shows them as current.
func TestDetailReportsWhenTheKeyOnDiskIsNotTheRecordedOne(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	priv := filepath.Join(ssh, "profiles", "work", "work_gh-ed25519")
	fp := mintPair(t, priv, "gh")
	ref := manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"}

	// Agreeing: the record names the key that is actually there.
	inv := inventory.New()
	inv.Record(fp, inventory.KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519",
	})
	d, err := New(&m, inv, ssh).Detail(ref)
	if err != nil {
		t.Fatal(err)
	}
	if d.DiskFingerprint != fp {
		t.Errorf("DiskFingerprint = %q, want the fingerprint of the .pub on disk (%q)", d.DiskFingerprint, fp)
	}
	if d.Mismatched() {
		t.Error("a record naming the key on disk is not a mismatch")
	}
	if d.FingerprintErr != "" {
		t.Errorf("FingerprintErr = %q, want none for a readable key", d.FingerprintErr)
	}

	// Disagreeing: the key was replaced behind the tool's back.
	stale := inventory.New()
	stale.Record("SHA256:whatever-was-here-before", inventory.KeyRecord{
		Profile: "work", Path: "~/.ssh/profiles/work/work_gh-ed25519", Type: "ed25519",
	})
	d, err = New(&m, stale, ssh).Detail(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Mismatched() {
		t.Fatalf("recorded %q vs on disk %q should be a mismatch", d.Fingerprint, d.DiskFingerprint)
	}

	// Neither half known is not a mismatch - an unminted key must not be reported
	// as one that was swapped out.
	cold, err := New(&m, inventory.New(), ssh).Detail(manifest.KeyRef{Profile: "vault", KeyName: "vault_cold-ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if cold.Mismatched() {
		t.Error("a key that is on neither side should not read as mismatched")
	}
}

// A .pub that will not fingerprint has to say why. Reported as a blank
// fingerprint it is indistinguishable from a key that was never minted, which
// sends the user to reconcile instead of to the corrupt file.
func TestAnUnreadablePublicKeyExplainsItself(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	ssh := t.TempDir()
	dir := filepath.Join(ssh, "profiles", "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"work_gh-ed25519":     "PRIVATE\n",
		"work_gh-ed25519.pub": "this is not a public key\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	d, err := New(&m, inventory.New(), ssh).Detail(manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if d.FingerprintErr == "" {
		t.Error("a malformed .pub should be explained, not left as a blank fingerprint")
	}
	if d.DiskFingerprint != "" {
		t.Errorf("DiskFingerprint = %q, want empty when it could not be read", d.DiskFingerprint)
	}
	if d.Mismatched() {
		t.Error("an unreadable .pub is not evidence that the key was replaced")
	}
}

// Two records can point at one identity path - a rotation whose bookkeeping was
// interrupted, an import over an existing key. The inventory is a map, so
// picking by iteration order made the same tree report different deployment
// status between runs of the same command. The tie is broken by lowest
// fingerprint: arbitrary, but the same every time.
func TestTwoRecordsAtOnePathResolveTheSameWayEveryTime(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	inv := inventory.New()
	const ident = "~/.ssh/profiles/work/work_gh-ed25519"
	inv.Record("SHA256:bbb", inventory.KeyRecord{
		Profile: "work", Path: ident, ExpiresOn: ptr("2027-12-31"),
		Deployments: []inventory.Deployment{{Target: "gh", Method: "manual", Verified: true}},
	})
	inv.Record("SHA256:aaa", inventory.KeyRecord{
		Profile: "work", Path: ident, ExpiresOn: ptr("2026-06-30"),
	})
	s := New(&m, inv, t.TempDir())

	for i := range 50 {
		row, err := s.Row(manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"})
		if err != nil {
			t.Fatal(err)
		}
		if row.Fingerprint != "SHA256:aaa" {
			t.Fatalf("run %d: fingerprint = %q, want the stable lowest one", i, row.Fingerprint)
		}
		// Every field has to come from that same record, not a mix of the two.
		if row.ExpiresOn != "2026-06-30" {
			t.Fatalf("run %d: expires_on = %q, taken from a different record than the fingerprint", i, row.ExpiresOn)
		}
		if len(row.Deployments) != 0 {
			t.Fatalf("run %d: deployments = %+v, taken from a different record than the fingerprint", i, row.Deployments)
		}
		if row.Status != query.NeedsRedeploy {
			t.Fatalf("run %d: status = %q, but the reported record has no deployments", i, row.Status)
		}
	}
}

func ptr(s string) *string { return &s }
