package configsvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

// profiles deliberately NOT alphabetical, to prove Check reports in file order.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git"}]},
    "alpha": {"key_scope": "per_service", "hosts": [{"alias": "a", "hostname": "a.com", "user": "u"}]}
  }
}`

func TestInSyncFormatHasCheck(t *testing.T) {
	r := &CheckResult{}
	if got := r.Format(); got != "config: in sync with the manifest ✓" {
		t.Errorf("in-sync format = %q (want the checkmark form, matching v1)", got)
	}
}

func TestCheckMissingInRenderOrder(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	// Empty ~/.ssh -> every rendered file is missing, reported in render order
	// (root config first, then profiles in file order: work, alpha).
	svc := New(t.TempDir(), &m, false)
	res, err := svc.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config", "profiles/work/config", "profiles/alpha/config"}
	if len(res.Missing) != len(want) {
		t.Fatalf("missing=%v want %v", res.Missing, want)
	}
	for i := range want {
		if res.Missing[i] != want[i] {
			t.Fatalf("missing order=%v want %v (file order, not sorted)", res.Missing, want)
		}
	}
	if res.InSync() {
		t.Error("empty tree must not be in sync")
	}
	if !strings.HasPrefix(res.Format(), "MISSING  config (") {
		t.Errorf("format should start with the root config MISSING line:\n%s", res.Format())
	}
}
