package query

import (
	"encoding/json"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
)

// profiles deliberately NOT in alphabetical order, to prove file order is kept.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [
      {"alias": "gh", "hostname": "github.com", "user": "git", "provider": "github", "tags": ["vcs","daily"]},
      {"alias": "box", "hostname": "10.0.0.2", "user": "deploy", "provider": "generic-ssh"}
    ]},
    "personal": {"key_scope": "shared", "key_name": "id_personal", "hosts": [
      {"alias": "vps", "hostname": "1.2.3.4", "user": "root", "provider": "digitalocean", "tags": ["daily"]}
    ]},
    "empty": {"key_scope": "per_service", "hosts": []}
  }
}`

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return &m
}

func TestProfileNamesFileOrder(t *testing.T) {
	m := loadManifest(t)
	got := m.ProfileNames()
	want := []string{"work", "personal", "empty"}
	if len(got) != len(want) {
		t.Fatalf("ProfileNames=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ProfileNames=%v want %v (file order, not sorted)", got, want)
		}
	}
}

func TestGroupsUnfiltered(t *testing.T) {
	m := loadManifest(t)
	q := New(m, inventory.New(), "")
	groups, err := q.Groups("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Empty profile included only when unfiltered.
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	if groups[0].Name != "work" || groups[1].Name != "personal" || groups[2].Name != "empty" {
		t.Fatalf("group order wrong: %s,%s,%s", groups[0].Name, groups[1].Name, groups[2].Name)
	}
	if !groups[2].Empty || len(groups[2].Rows) != 0 {
		t.Errorf("empty profile should be Empty with no rows")
	}
	// Provider labels and statuses (empty inventory -> all no-key).
	gh := groups[0].Rows[0]
	if gh.ProviderLabel != "github/vcs" || gh.Status != NoKey {
		t.Errorf("gh row=%+v", gh)
	}
	box := groups[0].Rows[1]
	if box.ProviderLabel != "generic-ssh/server" {
		t.Errorf("box label=%q want generic-ssh/server", box.ProviderLabel)
	}
	vps := groups[1].Rows[0]
	if vps.ProviderLabel != "digitalocean/vps" || vps.KeyName != "id_personal" {
		t.Errorf("vps row=%+v (shared key_name expected)", vps)
	}
}

func TestGroupsFilters(t *testing.T) {
	m := loadManifest(t)
	q := New(m, inventory.New(), "")

	// --type vcs -> only the github host; empty profile excluded when filtered.
	g, _ := q.Groups("", "", "vcs", "")
	if len(g) != 1 || len(g[0].Rows) != 1 || g[0].Rows[0].Alias != "gh" {
		t.Errorf("type=vcs filter wrong: %+v", g)
	}
	// --tag daily -> gh (work) and vps (personal).
	g, _ = q.Groups("", "", "", "daily")
	if len(g) != 2 {
		t.Errorf("tag=daily should match two profiles, got %d", len(g))
	}
	// --provider digitalocean -> only personal/vps.
	g, _ = q.Groups("", "digitalocean", "", "")
	if len(g) != 1 || g[0].Name != "personal" {
		t.Errorf("provider filter wrong: %+v", g)
	}
	// --profile work -> only work.
	g, _ = q.Groups("work", "", "", "")
	if len(g) != 1 || g[0].Name != "work" {
		t.Errorf("profile filter wrong: %+v", g)
	}
}

func TestDetailHostAndStatuses(t *testing.T) {
	m := loadManifest(t)
	inv := inventory.New()
	// A verified deployment on the github key -> deployed; vps key present but
	// unverified -> needs-redeploy.
	dep := []inventory.Deployment{{Target: "github", Method: "github-gh", Verified: true}}
	inv.Record("fp-gh", inventory.KeyRecord{
		Profile: "work", Path: m.IdentityFile("work", mustKey(t, m, "work", "gh")),
		Created: ptr("2026-01-01"), RotateAfterDays: 365, Deployments: dep,
	})
	inv.Record("fp-vps", inventory.KeyRecord{
		Profile: "personal", Path: m.IdentityFile("personal", "id_personal"),
	})
	q := New(m, inv, "")

	d, err := q.Detail("gh")
	if err != nil {
		t.Fatal(err)
	}
	hd, ok := d.(*HostDetail)
	if !ok {
		t.Fatalf("Detail(gh) type=%T want *HostDetail", d)
	}
	if hd.Status != Deployed || hd.Fingerprint == nil || *hd.Fingerprint != "fp-gh" {
		t.Errorf("gh detail status/fp wrong: %+v fp=%v", hd, hd.Fingerprint)
	}
	if len(hd.Deployments) != 1 || hd.Deployments[0].Method != "github-gh" {
		t.Errorf("gh deployments wrong: %+v", hd.Deployments)
	}

	// Group status reflects the inventory: vps -> needs-redeploy.
	g, _ := q.Groups("personal", "", "", "")
	if g[0].Rows[0].Status != NeedsRedeploy {
		t.Errorf("vps status=%q want needs-redeploy", g[0].Rows[0].Status)
	}

	// Profile selector -> ProfileSummary.
	d, _ = q.Detail("work")
	if ps, ok := d.(*ProfileSummary); !ok || ps.KeyScope != "per_service" || len(ps.Rows) != 2 {
		t.Errorf("Detail(work) wrong: %T %+v", d, d)
	}

	if _, err := q.Detail("nope"); err == nil {
		t.Error("Detail(nope) should error")
	}
}

func ptr(s string) *string { return &s }

func mustKey(t *testing.T, m *manifest.Manifest, profile, alias string) string {
	t.Helper()
	for _, h := range m.Profiles[profile].Hosts {
		if h.Alias == alias {
			k, err := m.ResolvedKeyName(profile, h)
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
	}
	t.Fatalf("no host %q in %q", alias, profile)
	return ""
}
