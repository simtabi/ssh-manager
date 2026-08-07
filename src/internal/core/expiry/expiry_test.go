package expiry

import (
	"strings"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
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

// TestComputeStates mirrors v1 compute_states classification and order.
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

// The boundaries, which the classification test does not reach.
// v1's expiry: days < 0 is overdue, days <=
// warn_window is due_soon, anything further out is ok. A key expiring *today*
// is due_soon, not overdue - it is still usable for the rest of the day.
func TestClassificationBoundaries(t *testing.T) {
	today := mustDate(t, "2026-06-16")
	cases := []struct {
		expires string
		want    string
		days    int
	}{
		{"2026-06-15", Overdue, -1}, // yesterday
		{"2026-06-16", DueSoon, 0},  // today: still usable
		{"2026-06-17", DueSoon, 1},
		{"2026-07-16", DueSoon, 30}, // exactly the warn window
		{"2026-07-17", OK, 31},      // one day past it
	}
	for _, c := range cases {
		inv := inventory.New()
		inv.Record("fp", inventory.KeyRecord{
			Profile: "work", Path: "/h/.ssh/profiles/work/k", ExpiresOn: sp(c.expires),
		})
		states := ComputeStates(inv, []int{7, 30}, today)
		if len(states) != 1 {
			t.Fatalf("%s: got %d states", c.expires, len(states))
		}
		if states[0].State != c.want {
			t.Errorf("%s: state = %q, want %q", c.expires, states[0].State, c.want)
		}
		if states[0].DaysRemaining == nil || *states[0].DaysRemaining != c.days {
			t.Errorf("%s: days = %v, want %d", c.expires, states[0].DaysRemaining, c.days)
		}
	}
}

// The warn window is the largest threshold, and 30 when none are configured.
func TestWarnWindowIsTheLargestThreshold(t *testing.T) {
	today := mustDate(t, "2026-06-16")
	inv := inventory.New()
	inv.Record("fp", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/k", ExpiresOn: sp("2026-07-06"), // 20 days out
	})

	if got := ComputeStates(inv, []int{1, 7, 30}, today)[0].State; got != DueSoon {
		t.Errorf("with a 30-day window, 20 days out should be due_soon, got %q", got)
	}
	if got := ComputeStates(inv, []int{1, 7}, today)[0].State; got != OK {
		t.Errorf("with a 7-day window, 20 days out should be ok, got %q", got)
	}
	if got := ComputeStates(inv, nil, today)[0].State; got != DueSoon {
		t.Errorf("with no thresholds the default window is 30 days, got %q", got)
	}
}

// Cadence is weekly until something needs attention. The notifier reads this to
// decide how often to interrupt.
func TestCadenceIsWeeklyUntilSomethingIsDue(t *testing.T) {
	today := mustDate(t, "2026-06-16")
	inv := inventory.New()
	inv.Record("fp-ok", inventory.KeyRecord{
		Profile: "work", Path: "/h/.ssh/profiles/work/k", ExpiresOn: sp("2027-01-01"),
	})
	if got := Cadence(ComputeStates(inv, []int{30}, today)); got != "weekly" {
		t.Errorf("cadence = %q, want weekly when nothing is due", got)
	}
	if got := Cadence(nil); got != "weekly" {
		t.Errorf("cadence of no keys = %q, want weekly", got)
	}
	if got := BannerLines(ComputeStates(inv, []int{30}, today)); len(got) != 0 {
		t.Errorf("nothing due should produce no banner: %v", got)
	}
}

// The banner names keys as profile/key, and the command it suggests has to be
// one the user can paste. A bare name is ambiguous when the same name exists in
// two profiles, which is the normal case here.
func TestBannerNamesKeysUnambiguously(t *testing.T) {
	today := mustDate(t, "2026-06-16")
	inv := inventory.New()
	inv.Record("fp-a", inventory.KeyRecord{
		Profile: "personal", Path: "/h/.ssh/profiles/personal/imani_github-ed25519",
		ExpiresOn: sp("2026-06-10"), // overdue by 6
	})
	inv.Record("fp-b", inventory.KeyRecord{
		Profile: "adelsaiq", Path: "/h/.ssh/profiles/adelsaiq/imani_github-ed25519",
		ExpiresOn: sp("2026-06-20"), // due in 4
	})
	lines := BannerLines(ComputeStates(inv, []int{30}, today))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per key needing attention: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"personal/imani_github-ed25519", "adelsaiq/imani_github-ed25519",
		"OVERDUE by 6 days", "expires in 4 days",
		"sshmgr rotate personal/imani_github-ed25519",
		"2026-06-10", "2026-06-20",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("banner should contain %q:\n%s", want, joined)
		}
	}
}

// Most urgent first, so the first line of a banner is the thing to deal with.
func TestStatesSortMostUrgentFirst(t *testing.T) {
	today := mustDate(t, "2026-06-16")
	inv := inventory.New()
	inv.Record("fp-far", inventory.KeyRecord{Profile: "w", Path: "/p/far", ExpiresOn: sp("2027-01-01")})
	inv.Record("fp-very-overdue", inventory.KeyRecord{Profile: "w", Path: "/p/vo", ExpiresOn: sp("2025-01-01")})
	inv.Record("fp-soon", inventory.KeyRecord{Profile: "w", Path: "/p/soon", ExpiresOn: sp("2026-06-20")})
	inv.Record("fp-unknown", inventory.KeyRecord{Profile: "w", Path: "/p/unk"})

	states := ComputeStates(inv, []int{30}, today)
	want := []string{"fp-very-overdue", "fp-soon", "fp-far", "fp-unknown"}
	for i, fp := range want {
		if states[i].Fingerprint != fp {
			t.Errorf("position %d = %s, want %s (order: %v)", i, states[i].Fingerprint, fp, fingerprints(states))
		}
	}
}

func fingerprints(states []Status) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, s.Fingerprint)
	}
	return out
}

// Ref is what every surface names a key by; without a profile it degrades to
// the bare name rather than emitting a leading slash.
func TestRef(t *testing.T) {
	if got := (Status{Profile: "work", KeyName: "k"}).Ref(); got != "work/k" {
		t.Errorf("Ref = %q", got)
	}
	if got := (Status{KeyName: "k"}).Ref(); got != "k" {
		t.Errorf("Ref with no profile = %q, want the bare name", got)
	}
}
