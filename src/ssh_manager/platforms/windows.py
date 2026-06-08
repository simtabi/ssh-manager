"""Windows strategy - ACLs (icacls), Task Scheduler (schtasks), toast notifications.

Windows is **first-class**: CI's ``windows-latest`` job runs the real
``icacls``/``schtasks`` primitives AND a full reconcile/perms/config end-to-end
(see tests/test_windows.py ``win32_only`` tests), and the flow logic is exercised
with the Windows platform on every OS. The security-critical piece is
``set_perms``: SSH on Windows refuses a private key that other principals can read,
so it strips inheritance and grants the current user only.
"""
from __future__ import annotations

import getpass
import os
from collections.abc import Mapping
from pathlib import Path

from ..util import proc
from .base import Platform

_PERM_HINT = "icacls ships with Windows; ensure it's on PATH"


class Windows(Platform):
    name = "windows"
    emits_use_keychain = False
    # First-class: the platform primitives (icacls/schtasks/toast) AND a full
    # reconcile/perms/config e2e are validated on real Windows by CI's windows-latest
    # job (tests/test_windows.py win32_only tests).
    first_class = True

    def ssh_dir(self) -> Path:
        # Path.home() resolves to %USERPROFILE% on Windows - where OpenSSH expects
        # ~/.ssh. The config home is the Windows-standard %APPDATA%\ssh-manager below.
        return Path.home() / ".ssh"

    def config_dir(self, env: Mapping[str, str] | None = None) -> Path:
        """Windows-standard roaming config: ``%APPDATA%\\ssh-manager`` (falls back to
        ``~/AppData/Roaming/ssh-manager`` if APPDATA is unset). ``env`` defaults to
        ``os.environ`` but is threaded through for consistent resolution."""
        source: Mapping[str, str] = os.environ if env is None else env
        appdata = source.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / "ssh-manager"

    def perms_ok(self, path: Path, mode: int) -> bool:
        # Windows perms are ACLs, not POSIX mode bits (``st_mode & 0o777`` is a
        # synthetic value here), so a POSIX comparison would flag every file.
        # Perms are enforced via icacls on write; treat existing files as ok.
        return path.exists()

    # Broad principals that must not retain access to a private key. icacls
    # /inheritance:r removes only *inherited* ACEs; an explicit ACE for one of these
    # would survive and Win32-OpenSSH would then reject the key, so strip them too.
    _BROAD_PRINCIPALS = ("Everyone", "Authenticated Users", "Users", "BUILTIN\\Users")

    def set_perms(self, path: Path, mode: int) -> None:
        """Restrict to the current user (Windows ACL equivalent of 600/700): drop
        inherited ACEs, grant only this user, and remove any lingering explicit
        grant to a broad principal. ``mode`` is advisory here - SSH wants no
        other-principal access on private keys, dirs, *or* configs."""
        proc.require("icacls", _PERM_HINT)
        user = os.environ.get("USERNAME") or getpass.getuser()
        proc.run_checked(["icacls", str(path), "/inheritance:r"])
        proc.run_checked(["icacls", str(path), "/grant:r", f"{user}:F"])
        for principal in self._BROAD_PRINCIPALS:
            # Best-effort: removing an ACE that isn't present is a harmless no-op.
            proc.run(["icacls", str(path), "/remove:g", principal])

    def install_scheduler(self, command: str, *, label: str = "ssh_manager.expiry") -> None:
        proc.require("schtasks", "schtasks ships with Windows")
        proc.run_checked([
            "schtasks", "/Create", "/TN", label, "/TR", command,
            "/SC", "DAILY", "/ST", "09:00", "/F",
        ])

    def notify(self, title: str, message: str) -> bool:
        if not proc.has("powershell"):
            return False
        script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$n=New-Object System.Windows.Forms.NotifyIcon;"
            "$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;"
            f"$n.ShowBalloonTip(10000,{_ps_str(title)},{_ps_str(message)},"
            "[System.Windows.Forms.ToolTipIcon]::Info)"
        )
        proc.run(["powershell", "-NoProfile", "-Command", script])
        return True


def _ps_str(text: str) -> str:
    """Quote a string as a PowerShell single-quoted literal (doubling quotes)."""
    return "'" + text.replace("'", "''") + "'"
