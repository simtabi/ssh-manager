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
	"github.com/simtabi/ssh-manager/internal/util/desktop"
	"github.com/simtabi/ssh-manager/internal/util/fs"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// Notifier computes and fires expiry reminders.
type Notifier struct {
	p        paths.Paths
	defaults manifest.Defaults
}

// New builds a Notifier.
func New(p paths.Paths, defaults manifest.Defaults) *Notifier {
	return &Notifier{p: p, defaults: defaults}
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

// Notify fires the cadence-gated desktop alert. Returns true if one was sent.
// Mirrors Notifier.notify.
func (n *Notifier) Notify(now time.Time, force bool) bool {
	states, _ := n.States(now)
	var attention []expiry.Status
	for _, s := range states {
		if s.NeedsAttention() {
			attention = append(attention, s)
		}
	}
	if len(attention) == 0 {
		return false
	}
	interval := 7 * 24 * time.Hour
	if expiry.Cadence(states) == "daily" {
		interval = 24 * time.Hour
	}
	last := parseT(n.read(n.p.NotifyCache())["notified"])
	if !(force || last.IsZero() || now.Sub(last) >= interval) {
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
		parts = append(parts, fmt.Sprintf("%s (%dd)", s.KeyName, days))
	}
	if !desktop.Notify("ssh-manager - keys due for rotation", strings.Join(parts, "; ")) {
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
