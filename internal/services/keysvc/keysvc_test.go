package keysvc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/query"
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
