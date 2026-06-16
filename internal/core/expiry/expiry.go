// Package expiry is the pure expiry-policy engine, ported from
// src/ssh_manager/core/expiry.py. A keypair does not self-expire; this computes
// the policy reminder (per key: expires_on, days_remaining, state).
package expiry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
)

// State values.
const (
	OK      = "ok"
	DueSoon = "due_soon"
	Overdue = "overdue"
	Unknown = "unknown"
)

const dateLayout = "2006-01-02"

// Status is one key's expiry policy state.
type Status struct {
	Fingerprint   string
	KeyName       string
	Profile       string
	Created       *string
	ExpiresOn     *string
	DaysRemaining *int
	State         string
}

// NeedsAttention is true for due_soon/overdue keys.
func (s Status) NeedsAttention() bool { return s.State == DueSoon || s.State == Overdue }

func keyName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ComputeStates returns per-key expiry status, most-urgent first. today should be
// a date (UTC midnight); warnBeforeDays is the manifest's warn thresholds.
func ComputeStates(inv *inventory.Inventory, warnBeforeDays []int, today time.Time) []Status {
	warnWindow := 30
	if len(warnBeforeDays) > 0 {
		warnWindow = warnBeforeDays[0]
		for _, d := range warnBeforeDays[1:] {
			if d > warnWindow {
				warnWindow = d
			}
		}
	}
	var out []Status
	for fp, rec := range inv.Keys {
		if inventory.IsArchivedPath(rec.Path) {
			continue // archived predecessor, not active
		}
		exp := rec.ExpiresOn
		if exp == nil && rec.Created != nil && *rec.Created != "" {
			if e, err := inventory.ComputeExpiry(*rec.Created, rec.RotateAfterDays); err == nil {
				exp = &e
			}
		}
		var parsed *time.Time
		if exp != nil {
			if t, err := time.Parse(dateLayout, *exp); err == nil {
				parsed = &t
			} else {
				exp = nil // malformed -> unknown (don't crash)
			}
		}
		if parsed == nil {
			out = append(out, Status{
				Fingerprint: fp, KeyName: keyName(rec.Path), Profile: rec.Profile,
				Created: rec.Created, State: Unknown,
			})
			continue
		}
		days := int(parsed.Sub(today).Hours() / 24)
		state := OK
		switch {
		case days < 0:
			state = Overdue
		case days <= warnWindow:
			state = DueSoon
		}
		d := days
		out = append(out, Status{
			Fingerprint: fp, KeyName: keyName(rec.Path), Profile: rec.Profile,
			Created: rec.Created, ExpiresOn: exp, DaysRemaining: &d, State: state,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := daysOrInf(out[i].DaysRemaining), daysOrInf(out[j].DaysRemaining)
		if di != dj {
			return di < dj
		}
		return out[i].Fingerprint < out[j].Fingerprint // deterministic tiebreak
	})
	return out
}

func daysOrInf(d *int) int {
	if d == nil {
		return 1 << 30
	}
	return *d
}

// Cadence is "daily" once any key needs attention, else "weekly".
func Cadence(states []Status) string {
	for _, s := range states {
		if s.NeedsAttention() {
			return "daily"
		}
	}
	return "weekly"
}

// BannerLines is one warning line per due/overdue key - the inline reminder.
func BannerLines(states []Status) []string {
	var lines []string
	for _, s := range states {
		if !s.NeedsAttention() {
			continue
		}
		days := 0
		if s.DaysRemaining != nil {
			days = *s.DaysRemaining
		}
		var when string
		if s.State == Overdue {
			d := days
			if d < 0 {
				d = -d
			}
			when = fmt.Sprintf("OVERDUE by %d days", d)
		} else {
			when = fmt.Sprintf("expires in %d days", days)
		}
		exp := ""
		if s.ExpiresOn != nil {
			exp = *s.ExpiresOn
		}
		lines = append(lines, fmt.Sprintf(
			"⚠ %s %s (%s) - run: sshmgr rotate %s", s.KeyName, when, exp, s.KeyName))
	}
	return lines
}
