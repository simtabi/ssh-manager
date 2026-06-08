"""Linux/Unix strategy - ssh-agent, systemd/cron, chmod, notify-send (first-class)."""
from __future__ import annotations

import os
from pathlib import Path

from ..util import proc
from .base import Platform

_SERVICE = """\
[Unit]
Description=ssh-manager key-expiry notifier

[Service]
Type=oneshot
ExecStart={command}
"""

_TIMER = """\
[Unit]
Description=ssh-manager key-expiry notifier (daily)

[Timer]
OnCalendar=*-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""


class Linux(Platform):
    name = "linux"
    emits_use_keychain = False
    first_class = True   # POSIX perms model + systemd/cron + notify-send

    def ssh_dir(self) -> Path:
        return Path.home() / ".ssh"

    def _systemd_user_dir(self) -> Path:
        # systemd looks for user units in $XDG_CONFIG_HOME/systemd/user (~/.config/...)
        # regardless of where ssh-manager keeps its own state.
        xdg = os.environ.get("XDG_CONFIG_HOME")
        return (Path(xdg) if xdg else Path.home() / ".config") / "systemd" / "user"

    def set_perms(self, path: Path, mode: int) -> None:
        os.chmod(path, mode)

    def install_scheduler(self, command: str, *, label: str = "ssh_manager.expiry") -> None:
        """Register a daily job that runs ``command`` - a systemd --user timer if
        available, else a cron entry."""
        if proc.has("systemctl"):
            self._install_systemd(command, label)
        elif proc.has("crontab"):
            self._install_cron(command, label)
        else:
            raise NotImplementedError(
                "no scheduler found: install systemd (systemctl) or cron (crontab)")

    def _install_systemd(self, command: str, label: str) -> None:
        unit_dir = self._systemd_user_dir()
        unit_dir.mkdir(parents=True, exist_ok=True)
        # systemd treats `%` in ExecStart as a specifier prefix; `%%` is a literal %.
        (unit_dir / f"{label}.service").write_text(
            _SERVICE.format(command=command.replace("%", "%%")), encoding="utf-8")
        (unit_dir / f"{label}.timer").write_text(_TIMER, encoding="utf-8")
        proc.run(["systemctl", "--user", "daemon-reload"])
        proc.run_checked(["systemctl", "--user", "enable", "--now", f"{label}.timer"])
        self._remove_cron(label)   # don't let a stale cron entry double-fire

    def _install_cron(self, command: str, label: str) -> None:
        self._remove_systemd(label)   # don't let a stale timer double-fire
        marker = f"# {label}"
        current = proc.run(["crontab", "-l"])
        existing = current.stdout.splitlines() if current.returncode == 0 else []
        kept = [ln for ln in existing if marker not in ln]
        # In a crontab the command is everything up to an unescaped `%` (which cron
        # turns into a newline + stdin); escape any literal `%` in the path.
        escaped = command.replace("%", "\\%")
        kept.append(f"0 9 * * * {escaped} {marker}")
        proc.run_checked(["crontab", "-"], input_="\n".join(kept) + "\n")

    def _remove_cron(self, label: str) -> None:
        if not proc.has("crontab"):
            return
        current = proc.run(["crontab", "-l"])
        if current.returncode != 0:
            return
        marker = f"# {label}"
        kept = [ln for ln in current.stdout.splitlines() if marker not in ln]
        proc.run(["crontab", "-"], input_="\n".join(kept) + ("\n" if kept else ""))

    def _remove_systemd(self, label: str) -> None:
        if proc.has("systemctl"):
            proc.run(["systemctl", "--user", "disable", "--now", f"{label}.timer"])
        unit_dir = self._systemd_user_dir()
        for unit in (f"{label}.service", f"{label}.timer"):
            (unit_dir / unit).unlink(missing_ok=True)

    def notify(self, title: str, message: str) -> bool:
        if not proc.has("notify-send"):
            return False
        # notify-send renders Pango markup in the body, so escape &<> (a key name
        # like "a&b<c>" would otherwise render wrong or be dropped).
        body = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        proc.run(["notify-send", "--", title, body], timeout=10)
        return True
