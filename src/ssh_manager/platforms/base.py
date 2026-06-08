"""Platform interface: paths, perms, agent, scheduler, notification.

Strategy pattern: every OS-specific action routes through here so Linux/Windows
are a small delta, never a rewrite. ``emits_use_keychain`` is what decides
whether the renderer emits the macOS-only ``UseKeychain`` line.
"""
from __future__ import annotations

import abc
import os
from collections.abc import Mapping
from pathlib import Path


class Platform(abc.ABC):
    name: str = "base"
    emits_use_keychain: bool = False
    first_class: bool = False  # fully built+tested? (warn on non-first-class OSes)

    @abc.abstractmethod
    def ssh_dir(self) -> Path: ...

    def config_dir(self, env: Mapping[str, str] | None = None) -> Path:
        """The per-user ssh-manager home, in the OS-standard config location (single
        app folder ``ssh-manager``). Unix/macOS follow the XDG Base Directory spec:
        ``$XDG_CONFIG_HOME/ssh-manager`` if set, else ``~/.config/ssh-manager``. Windows
        overrides this to ``%APPDATA%\\ssh-manager``. ``$SSH_MANAGER_HOME`` (handled in
        util.paths) overrides everything. ``env`` (defaults to ``os.environ``) is
        threaded through so a programmatic caller gets consistent resolution."""
        source: Mapping[str, str] = os.environ if env is None else env
        xdg = source.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        return base / "ssh-manager"

    @abc.abstractmethod
    def set_perms(self, path: Path, mode: int) -> None: ...

    def perms_ok(self, path: Path, mode: int) -> bool:
        """Whether ``path`` already has the expected mode. The POSIX default
        compares the low 9 mode bits; platforms whose perms aren't POSIX modes
        (Windows ACLs) override this."""
        return (path.stat().st_mode & 0o777) == mode

    @abc.abstractmethod
    def install_scheduler(self, command: str, *, label: str = "ssh_manager.expiry") -> None: ...

    @abc.abstractmethod
    def notify(self, title: str, message: str) -> bool:
        """Post a desktop notification. Returns True if one was actually
        dispatched, False if no notification backend is available."""
