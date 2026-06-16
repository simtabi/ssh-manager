package expiry

import (
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
)

func sp(s string) *string { return &s }

func mustDate(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(dateLayout, s)
	if err != nil {
		t.Fatalf("bad date %q: %v", s, err)
	}
	return d
}

// TestComputeStates mirrors the Python compute_states classification and order.
func TestComputeStates(t *testing.T) {
	inv := inventory.New()
	// expires_on explicit, derive nothing.
	inv.Record("fp-overdue", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/a", ExpiresOn: sp("2026-01-01"),
	})
	inv.Record("fp-duesoon", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/b", ExpiresOn: sp("2026-07-01"),
	})
	inv.Record("fp-ok", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/c", ExpiresOn: sp("2027-01-01"),
	})
	// derived from created + rotate_after_days (no explicit expires_on).
	inv.Record("fp-derived", inventory.KeyRecord{
		Profile: "home", Path: "/h/.ssh/profiles/home/d",
		Created: sp("2025-01-01"), RotateAfterDays: 365, // -> 2026-01-01 -> overdue
	})
	// no created, no expires_on -> unknown.
	inv.Record("fp-unknown", inventory.KeyRecord{
		Profile: "home", Path: "/h/.ssh/profiles/home/e",
	})
	// malformed date -> unknown, not a crash.
	inv.Record("fp-malformed", inventory.KeyRecord{
		Profile: "home", Path: "/h/.ssh/profiles/home/f", ExpiresOn: sp("not-a-date"),
	})
	// archived predecessor -> skipped entirely.
	inv.Record("fp-archived", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/old/a", ExpiresOn: sp("2026-01-01"),
	})

	today := mustDate(t, "2026-06-16")
	states := ComputeStates(inv, []int{7, 30}, today)

	wantState := map[string]string{
		"fp-overdue":   Overdue,
		"fp-duesoon":   DueSoon,
		"fp-ok":        OK,
		"fp-derived":   Overdue,
		"fp-unknown":   Unknown,
		"fp-malformed": Unknown,
	}
	if len(states) != len(wantState) {
		t.Fatalf("got %d states, want %d (archived must be skipped)", len(states), len(wantState))
	}
	for _, s := range states {
		if want := wantState[s.Fingerprint]; want != s.State {
			t.Errorf("%s: state=%q want %q (days=%v)", s.Fingerprint, s.State, want, s.DaysRemaining)
		}
		if s.Fingerprint == "fp-duesoon" && (s.DaysRemaining == nil || *s.DaysRemaining != 15) {
			t.Errorf("fp-duesoon days=%v want 15", s.DaysRemaining)
		}
	}
	// Sorted most-urgent first: unknown (no days) must sort last.
	if states[len(states)-1].State != Unknown {
		t.Errorf("unknown key must sort last, got %q", states[len(states)-1].State)
	}

	if got := Cadence(states); got != "daily" {
		t.Errorf("cadence=%q want daily (overdue/due_soon present)", got)
	}
	// fp-overdue + fp-derived (both overdue) + fp-duesoon all need attention.
	if lines := BannerLines(states); len(lines) != 3 {
		t.Errorf("banner lines=%d want 3 (2 overdue + 1 due_soon)", len(lines))
	}
}
