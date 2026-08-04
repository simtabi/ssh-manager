package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/services/keysvc"
	"github.com/simtabi/ssh-manager/internal/services/query"
)

// The table is where a dangling key becomes visible, so every state a row can
// carry has to reach the screen - including the ones that read as "fine" until
// you notice no host uses the key.
func TestKeyTableShowsStateAndDanglingNotes(t *testing.T) {
	rows := []keysvc.Row{
		{
			Ref:         manifest.KeyRef{Profile: "work", KeyName: "work_gh-ed25519"},
			Type:        "ed25519",
			Fingerprint: "SHA256:abc",
			ExpiresOn:   "2027-01-01",
			Hosts:       []string{"gh", "gh-alt"},
			Status:      query.Deployed,
			// A present, recorded pair: no notes.
			PrivateOnDisk: true, PublicOnDisk: true, Recorded: true,
		},
		{
			Ref:    manifest.KeyRef{Profile: "vault", KeyName: "vault_cold-ed25519"},
			Type:   "ed25519",
			Status: query.NoKey,
		},
	}
	var out bytes.Buffer
	writeKeyTable(&out, rows)
	got := out.String()

	for _, want := range []string{
		"KEY", "TYPE", "FINGERPRINT", "EXPIRES", "HOSTS", "STATE",
		"work/work_gh-ed25519", "SHA256:abc", "2027-01-01", "gh,gh-alt", query.Deployed,
		"vault/vault_cold-ed25519", query.NoKey, keyaudit.Missing, keyaudit.Unwired,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("key table missing %q:\n%s", want, got)
		}
	}
	// Empty columns render as a dash, not as blank runs the eye has to count.
	var vault string
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "vault/") {
			vault = line
		}
	}
	dashes := 0
	for _, f := range strings.Fields(vault) {
		if f == "-" {
			dashes++
		}
	}
	if dashes != 3 { // fingerprint, expires, hosts
		t.Errorf("unset columns should render as dashes, found %d in %q", dashes, vault)
	}
}

func TestKeyTableEmptyTellsYouWhatToRun(t *testing.T) {
	var out bytes.Buffer
	writeKeyTable(&out, nil)
	if !strings.Contains(out.String(), "sshmgr key add") {
		t.Errorf("an empty table should point at the command that fixes it: %q", out.String())
	}
}
