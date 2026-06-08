"""Pure expiry engine + notifier cadence/banner."""
from __future__ import annotations

from datetime import date, datetime

from ssh_manager.core.expiry import (
    DUE_SOON,
    OK,
    OVERDUE,
    banner_lines,
    cadence,
    compute_states,
)
from ssh_manager.core.inventory import Inventory, KeyRecord
from ssh_manager.services.facade import SshManagerService

TODAY = date(2026, 6, 4)
WARN = [30, 14, 7, 1]


def _inv() -> Inventory:
    inv = Inventory()
    inv.record("SHA256:ok", KeyRecord(
        profile="p", path="~/.ssh/profiles/p/p_ok-ed25519",
        created="2026-01-01", expires_on="2027-01-01"))
    inv.record("SHA256:soon", KeyRecord(
        profile="p", path="~/.ssh/profiles/p/p_soon-ed25519",
        created="2025-06-14", expires_on="2026-06-14"))   # +10 days
    inv.record("SHA256:over", KeyRecord(
        profile="p", path="~/.ssh/profiles/p/p_over-ed25519",
        created="2025-06-01", expires_on="2026-06-01"))   # -3 days
    return inv


def test_states_classify_and_sort() -> None:
    states = compute_states(_inv(), warn_before_days=WARN, today=TODAY)
    by_name = {s.key_name: s for s in states}
    assert by_name["p_ok-ed25519"].state == OK
    assert by_name["p_soon-ed25519"].state == DUE_SOON
    assert by_name["p_soon-ed25519"].days_remaining == 10
    assert by_name["p_over-ed25519"].state == OVERDUE
    assert by_name["p_over-ed25519"].days_remaining == -3
    # sorted most-urgent (fewest days) first
    assert states[0].key_name == "p_over-ed25519"


def test_cadence_and_banner() -> None:
    states = compute_states(_inv(), warn_before_days=WARN, today=TODAY)
    assert cadence(states) == "daily"            # something is in the warn window
    lines = banner_lines(states)
    assert any("OVERDUE" in ln for ln in lines)
    assert any("expires in 10 days" in ln for ln in lines)
    assert all(ln.startswith("⚠") for ln in lines)
    # an all-ok inventory -> weekly, no banner
    ok_only = Inventory()
    ok_only.record("SHA256:ok", KeyRecord(
        profile="p", path="~/.ssh/profiles/p/p_ok-ed25519",
        created="2026-01-01", expires_on="2027-01-01"))
    ok_states = compute_states(ok_only, warn_before_days=WARN, today=TODAY)
    assert cadence(ok_states) == "weekly"
    assert banner_lines(ok_states) == []


def test_archived_old_keys_are_skipped() -> None:
    inv = Inventory()
    inv.record("SHA256:archived", KeyRecord(
        profile="p", path="~/.ssh/profiles/p/old/p_x-ed25519",
        created="2025-06-01", expires_on="2026-06-01"))
    assert compute_states(inv, warn_before_days=WARN, today=TODAY) == []


def test_freshly_reconciled_keys_are_ok(svc: SshManagerService) -> None:
    svc.reconcile()
    states = svc.expiry_states()
    assert states and all(s.state == OK for s in states)   # ~365 days -> all ok


def test_notifier_banner_debounce_and_cadence(svc: SshManagerService, monkeypatch) -> None:
    from ssh_manager.services.notifier import Notifier
    overdue = Inventory()
    overdue.record("SHA256:over", KeyRecord(
        profile="work", path="~/.ssh/profiles/work/work_unc-ed25519",
        created="2025-06-01", expires_on="2026-06-01"))
    overdue.save(svc.paths.inventory)
    fired: list = []
    monkeypatch.setattr("ssh_manager.platforms.macos.MacOS.notify",
                        lambda self, t, m: fired.append((t, m)) or True)
    n = Notifier(svc.platform, svc.paths, svc.manifest().defaults)
    now = datetime(2026, 6, 4, 9, 0, 0)

    banner = n.banner(now=now)
    assert "work_unc-ed25519" in banner and "OVERDUE" in banner
    # scheduled notify fires once, then is debounced within the cadence interval
    assert n.notify(now=now, force=True) is True
    assert fired
    assert n.notify(now=now) is False
    # debounce: change inventory but the cached banner stands until the window passes
    Inventory().save(svc.paths.inventory)
    assert n.banner(now=now) == banner


def test_notify_reports_false_when_no_backend(svc: SshManagerService, monkeypatch) -> None:
    from ssh_manager.services.notifier import Notifier
    overdue = Inventory()
    overdue.record("SHA256:over", KeyRecord(
        profile="work", path="~/.ssh/profiles/work/work_unc-ed25519",
        created="2025-06-01", expires_on="2026-06-01"))
    overdue.save(svc.paths.inventory)
    monkeypatch.setattr("ssh_manager.platforms.macos.MacOS.notify",
                        lambda self, t, m: False)            # no notifier backend
    n = Notifier(svc.platform, svc.paths, svc.manifest().defaults)
    now = datetime(2026, 6, 4, 9, 0, 0)
    # no backend -> not reported as "sent", and the cadence cache isn't written,
    # so it will try again next time (not silently debounced into never-firing)
    assert n.notify(now=now, force=True) is False
    assert n.notify(now=now, force=True) is False
