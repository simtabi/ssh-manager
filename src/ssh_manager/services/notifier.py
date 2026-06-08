"""Expiry checks + desktop/scheduled alerts. Uses the platform layer.

Three surfaces, all driven by the pure expiry engine:
- ``banner`` - the cheap inline reminder, debounced via ``expiry_check.debounce_hours``;
- ``notify`` - the scheduled desktop alert, cadence-gated (weekly normally, daily
  once any key is inside its warn window) with a last-notified debounce;
- ``install`` - register the launchd/cron job that runs ``sshmgr audit --notify``.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from ..core.expiry import ExpiryStatus, banner_lines, cadence, compute_states
from ..core.inventory import Inventory
from ..core.manifest import Defaults
from ..platforms.base import Platform
from ..util import jsonstore
from ..util.lock import advisory_lock
from ..util.paths import Paths


class Notifier:
    def __init__(self, platform: Platform, paths: Paths, defaults: Defaults) -> None:
        self._platform = platform
        self._paths = paths
        self._defaults = defaults

    def states(self, *, now: datetime) -> list[ExpiryStatus]:
        inv = Inventory.load(self._paths.inventory)
        return compute_states(
            inv, warn_before_days=self._defaults.warn_before_days, today=now.date()
        )

    # inline banner (debounced)
    def banner(self, *, now: datetime) -> str:
        if not self._defaults.expiry_check.enabled:
            return ""
        cache = self._read(self._paths.expiry_cache)
        debounce = timedelta(hours=self._defaults.expiry_check.debounce_hours)
        checked = _parse(cache.get("checked"))
        if checked is not None and now - checked < debounce:
            cached = cache.get("banner")
            return "\n".join(cached) if isinstance(cached, list) else ""
        lines = banner_lines(self.states(now=now))
        self._write(self._paths.expiry_cache, {"checked": now.isoformat(), "banner": lines})
        return "\n".join(lines)

    # scheduled desktop alert (cadence-gated)
    def notify(self, *, now: datetime, force: bool = False) -> bool:
        states = self.states(now=now)
        attention = [s for s in states if s.needs_attention]
        if not attention:
            return False
        interval = timedelta(days=1 if cadence(states) == "daily" else 7)
        last = _parse(self._read(self._paths.notify_cache).get("notified"))
        if not (force or last is None or now - last >= interval):
            return False
        if not self._defaults.expiry_check.desktop_notify:
            return False
        title = "ssh-manager - keys due for rotation"
        msg = "; ".join(f"{s.key_name} ({s.days_remaining}d)" for s in attention[:4])
        if not self._platform.notify(title, msg):
            return False   # no notifier backend - don't mark as notified, retry later
        self._write(self._paths.notify_cache, {"notified": now.isoformat()})
        return True

    def test(self) -> bool:
        return self._platform.notify(
            "ssh-manager", "test notification - the notifier is wired up.")

    def install(self, command: str) -> None:
        self._platform.install_scheduler(command, label="ssh_manager.expiry")

    # tiny json cache helpers
    def _read(self, path: Path) -> dict[str, object]:
        if not path.exists():
            return {}
        try:
            data = jsonstore.read_json(path)
        except ValueError:
            return {}
        return dict(data) if isinstance(data, dict) else {}

    def _write(self, path: Path, data: dict[str, object]) -> None:
        # Under the advisory lock so a scheduled `audit --notify` and a manual run
        # can't race on the cache. Writes are debounced (rare).
        with advisory_lock(self._paths.lock_file):
            jsonstore.write_json_atomic(path, data)


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
