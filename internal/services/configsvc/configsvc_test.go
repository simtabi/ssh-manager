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

func TestCheckMissingSingleFile(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	// Empty ~/.ssh -> the one rendered file (everything is inline now) is missing.
	svc := New(t.TempDir(), &m, false)
	res, err := svc.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config"}
	if len(res.Missing) != len(want) || res.Missing[0] != want[0] {
		t.Fatalf("missing=%v want %v", res.Missing, want)
	}
	if res.InSync() {
		t.Error("empty tree must not be in sync")
	}
	if !strings.HasPrefix(res.Format(), "MISSING  config (") {
		t.Errorf("format should start with the root config MISSING line:\n%s", res.Format())
	}
}
