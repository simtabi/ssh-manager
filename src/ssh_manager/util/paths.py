"""Home-dir resolution + .env loading.

Resolution (highest precedence first):
  1. ``$SSH_MANAGER_HOME`` (alias ``$SSH_MANAGER_CONFIG_DIR``), absolutized - explicit override.
  2. the OS-standard config dir + single app folder ``ssh-manager`` (``platform.config_dir()``):
       Unix/macOS: ``$XDG_CONFIG_HOME/ssh-manager`` if set, else ``~/.config/ssh-manager``
       Windows:    ``%APPDATA%\\ssh-manager``
A legacy ``~/.sshmgr`` home is auto-migrated to (2) on first run (see
``SshManagerService._migrate_legacy_home``). There is no project-local mode - one home
is used everywhere. The :class:`Paths` bundle is the single place layout is
computed, so every service agrees on where state lives.

One folder holds all of a user's state - config, secrets, logs, snapshots:

    <home>/
    |-- manifest.json inventory.json     (manifest is the source of truth)
    |-- providers.json                   (optional; else the shipped default catalog)
    |-- .env  age-identity.txt           (secrets, 0600)
    |-- log/audit.log
    |-- snapshots/
    |-- dist/    (exported encrypted bundles - ssh-manager-YYYYMMDD.age)
    `-- .state/  (.lock, expiry-cache.json, notify-cache.json)
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..platforms.base import Platform


@dataclass(frozen=True)
class Paths:
    """Resolved on-disk locations for one invocation."""

    ssh_dir: Path
    config_dir: Path        # the per-user home (OS-standard ssh-manager dir, or $SSH_MANAGER_HOME)

    @property
    def home(self) -> Path:
        return self.config_dir

    # config (the source of truth)
    @property
    def manifest(self) -> Path:
        return self.config_dir / "manifest.json"

    @property
    def inventory(self) -> Path:
        return self.config_dir / "inventory.json"

    @property
    def providers(self) -> Path:
        return self.config_dir / "providers.json"

    # secrets
    @property
    def env_file(self) -> Path:
        return self.config_dir / ".env"

    @property
    def env_example(self) -> Path:
        return self.config_dir / ".env-example"

    @property
    def age_identity(self) -> Path:
        return self.config_dir / "age-identity.txt"

    # logs
    @property
    def log_dir(self) -> Path:
        return self.config_dir / "log"

    @property
    def audit_log(self) -> Path:
        return self.log_dir / "audit.log"

    # backups
    @property
    def snapshots_dir(self) -> Path:
        return self.config_dir / "snapshots"

    # exported artifacts (encrypted bundles) live under the home, never the cwd
    @property
    def dist_dir(self) -> Path:
        return self.config_dir / "dist"

    # transient state
    @property
    def state_dir(self) -> Path:
        return self.config_dir / ".state"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / ".lock"

    @property
    def expiry_cache(self) -> Path:
        return self.state_dir / "expiry-cache.json"

    @property
    def notify_cache(self) -> Path:
        return self.state_dir / "notify-cache.json"


def resolve_config_dir(platform: Platform, *,
                       env: dict[str, str] | None = None,
                       cwd: Path | None = None) -> Path:
    """Resolve the per-user home: ``$SSH_MANAGER_HOME`` / ``$SSH_MANAGER_CONFIG_DIR``
    (absolutized) if set, else the OS-standard config dir + ``ssh-manager`` folder
    (``platform.config_dir()`` -> ``~/.config/ssh-manager`` on Unix/macOS,
    ``%APPDATA%\\ssh-manager`` on Windows). No project-local ``./config`` mode; a legacy
    ``~/.sshmgr`` is auto-migrated by the service on first run."""
    source: Mapping[str, str] = os.environ if env is None else env
    override = source.get("SSH_MANAGER_HOME") or source.get("SSH_MANAGER_CONFIG_DIR")
    if override:
        p = Path(override).expanduser()
        if not p.is_absolute():
            p = (cwd or Path.cwd()) / p
        return p
    return platform.config_dir(env=source)


def resolve_paths(platform: Platform, *,
                  env: dict[str, str] | None = None,
                  cwd: Path | None = None,
                  ssh_dir: Path | None = None) -> Paths:
    """Build the full :class:`Paths` bundle for this invocation."""
    config_dir = resolve_config_dir(platform, env=env, cwd=cwd)
    return Paths(ssh_dir=ssh_dir or platform.ssh_dir(), config_dir=config_dir)


def load_env(env_file: Path) -> None:
    """Load the ``.env`` into the process env if present (best-effort)."""
    if not env_file.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - dotenv is a hard dep, defensive
        return
    load_dotenv(env_file, override=False)
