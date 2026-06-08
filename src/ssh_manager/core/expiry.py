"""Expiry policy engine - pure, no I/O.

A raw SSH keypair does not self-expire; this is a *policy reminder* we compute and
surface. From the inventory we derive, per key, ``expires_on`` and
``days_remaining`` and a ``state`` ∈ {ok, due_soon, overdue}. ``due_soon`` fires
once a key is within the warn window (the largest ``warn_before_days`` threshold).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .inventory import Inventory, compute_expiry, is_archived_path

OK = "ok"
DUE_SOON = "due_soon"
OVERDUE = "overdue"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class ExpiryStatus:
    fingerprint: str
    key_name: str
    profile: str
    created: str | None
    expires_on: str | None
    days_remaining: int | None
    state: str

    @property
    def needs_attention(self) -> bool:
        return self.state in (DUE_SOON, OVERDUE)


def _key_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def compute_states(inventory: Inventory, *, warn_before_days: list[int],
                   today: date) -> list[ExpiryStatus]:
    """Per-key expiry status, sorted most-urgent first."""
    warn_window = max(warn_before_days) if warn_before_days else 30
    out: list[ExpiryStatus] = []
    for fp, rec in inventory.keys.items():
        if is_archived_path(rec.path):   # archived predecessor - not active, skip
            continue
        exp = rec.expires_on
        try:
            if exp is None and rec.created:
                exp = compute_expiry(rec.created, rec.rotate_after_days)
            parsed = date.fromisoformat(exp) if exp is not None else None
        except ValueError:
            # A hand-edited inventory with a malformed date shouldn't crash expiry/
            # audit - surface it as UNKNOWN instead of raising.
            parsed = None
        if parsed is None:
            out.append(ExpiryStatus(fp, _key_name(rec.path), rec.profile,
                                    rec.created, None, None, UNKNOWN))
            continue
        days = (parsed - today).days
        if days < 0:
            state = OVERDUE
        elif days <= warn_window:
            state = DUE_SOON
        else:
            state = OK
        out.append(ExpiryStatus(fp, _key_name(rec.path), rec.profile,
                                rec.created, exp, days, state))
    out.sort(key=lambda s: (s.days_remaining if s.days_remaining is not None else 10**9))
    return out


def cadence(states: list[ExpiryStatus]) -> str:
    """Notifier cadence: 'daily' once any key is in the warn window, else 'weekly'."""
    return "daily" if any(s.needs_attention for s in states) else "weekly"


def banner_lines(states: list[ExpiryStatus]) -> list[str]:
    """One ⚠ line per due/overdue key - the inline reminder."""
    lines: list[str] = []
    for s in states:
        if not s.needs_attention:
            continue
        if s.state == OVERDUE:
            when = f"OVERDUE by {abs(s.days_remaining or 0)} days"
        else:
            when = f"expires in {s.days_remaining} days"
        lines.append(
            f"⚠ {s.key_name} {when} ({s.expires_on}) - run: sshmgr rotate {s.key_name}"
        )
    return lines
