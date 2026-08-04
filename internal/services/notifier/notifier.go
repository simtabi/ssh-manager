// Package notifier drives the expiry surfaces from the pure expiry engine, ported
// from services/notifier.py: States (per-key expiry), Banner (the debounced inline
// reminder), and Notify (the cadence-gated desktop alert). Scheduler install lives
// with the platform layer (the notify verb).
package notifier

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/expiry"
	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
	"github.com/simtabi/ssh-manager/internal/util/desktop"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Notifier computes and fires the reminders.
type Notifier struct {
	p        paths.Paths
	m        *manifest.Manifest // nil when there is no manifest to audit against
	defaults manifest.Defaults
}

// New builds a Notifier over a manifest. It takes the whole manifest rather than
// just its defaults because the daily alert covers dangling keys as well as
// expiry, and deciding a key is dangling needs the profiles and hosts. m may be
// nil, in which case only expiry is reported.
func New(p paths.Paths, m *manifest.Manifest) *Notifier {
	n := &Notifier{p: p, m: m}
	if m != nil {
		n.defaults = m.Defaults
	}
	return n
}

// dateOf is the calendar date of now at UTC midnight (matches Python now.date()).
func dateOf(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// States returns per-key expiry status as of now. Mirrors Notifier.states.
func (n *Notifier) States(now time.Time) ([]expiry.Status, error) {
	inv, err := inventory.Load(n.p.Inventory())
	if err != nil {
		return nil, err
	}
	return expiry.ComputeStates(inv, n.defaults.WarnBeforeDays, dateOf(now)), nil
}

// Banner returns the cheap, debounced inline reminder (empty when nothing is due
// or the debounce window hasn't elapsed). Mirrors Notifier.banner.
func (n *Notifier) Banner(now time.Time) string {
	if !n.defaults.ExpiryCheck.Enabled {
		return ""
	}
	cache := n.read(n.p.ExpiryCache())
	debounce := time.Duration(n.defaults.ExpiryCheck.DebounceHours) * time.Hour
	if checked := parseT(cache["checked"]); !checked.IsZero() && now.Sub(checked) < debounce {
		if cached, ok := cache["banner"].([]any); ok {
			return joinAny(cached)
		}
		return ""
	}
	states, _ := n.States(now)
	lines := expiry.BannerLines(states)
	n.write(n.p.ExpiryCache(), map[string]any{"checked": now.Format(time.RFC3339), "banner": lines})
	return strings.Join(lines, "\n")
}

// Dangling returns the blocking dangling-key findings, or none when there is no
// manifest to audit against. Only the blocking ones: a daily desktop alert is
// for a key that has stopped working, not for one that has yet to be minted.
func (n *Notifier) Dangling() []keyaudit.Finding {
	if n.m == nil {
		return nil
	}
	inv, err := inventory.Load(n.p.Inventory())
	if err != nil {
		return nil
	}
	rep, err := keyaudit.New(n.m, inv, n.p.SSHDir).Audit(false)
	if err != nil {
		return nil
	}
	var out []keyaudit.Finding
	for _, f := range rep.Findings {
		if keyaudit.Blocking(f.State) {
			out = append(out, f)
		}
	}
	return out
}

// Notify fires the cadence-gated desktop alert. Returns true if one was sent.
//
// It covers dangling keys as well as expiry. An expiring key eventually stops
// working; a dangling one already has, and it was the only class of problem the
// daily reminder could not tell you about - so the one surface that reaches a
// user who is not running sshmgr now reports both.
func (n *Notifier) Notify(now time.Time, force bool) bool {
	states, _ := n.States(now)
	var attention []expiry.Status
	for _, s := range states {
		if s.NeedsAttention() {
			attention = append(attention, s)
		}
	}
	dangling := n.Dangling()
	if len(attention) == 0 && len(dangling) == 0 {
		return false
	}
	// Expiry sets the pace when it is the urgent half; a dangling key does not
	// get worse by the day, so on its own it stays weekly.
	interval := 7 * 24 * time.Hour
	if expiry.Cadence(states) == "daily" {
		interval = 24 * time.Hour
	}
	last := parseT(n.read(n.p.NotifyCache())["notified"])
	// Not yet due: something fired recently and this run was not forced.
	if !force && !last.IsZero() && now.Sub(last) < interval {
		return false
	}
	if !n.defaults.ExpiryCheck.DesktopNotify {
		return false
	}
	var parts []string
	for i, s := range attention {
		if i >= 4 {
			break
		}
		days := 0
		if s.DaysRemaining != nil {
			days = *s.DaysRemaining
		}
		parts = append(parts, fmt.Sprintf("%s (%dd)", s.Ref(), days))
	}
	for i, f := range dangling {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("+%d more dangling", len(dangling)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s is %s", f.Subject, f.State))
	}
	title := "ssh-manager - keys due for rotation"
	switch {
	case len(attention) == 0:
		title = "ssh-manager - dangling keys"
	case len(dangling) > 0:
		title = "ssh-manager - keys need attention"
	}
	if !desktop.Notify(title, strings.Join(parts, "; ")) {
		return false // no backend - don't mark notified, retry later
	}
	n.write(n.p.NotifyCache(), map[string]any{"notified": now.Format(time.RFC3339)})
	return true
}

// Test posts a test desktop notification.
func (n *Notifier) Test() bool {
	return desktop.Notify("ssh-manager", "test notification - the notifier is wired up.")
}

func (n *Notifier) read(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return map[string]any{}
	}
	return m
}

func (n *Notifier) write(path string, data map[string]any) {
	b, _ := json.MarshalIndent(data, "", "  ")
	_ = fs.WriteTextAtomic(path, string(b)+"\n", 0o600)
}

func parseT(v any) time.Time {
	s, ok := v.(string)
	if !ok {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func joinAny(items []any) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}
