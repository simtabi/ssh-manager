"""Per-user home resolution + the OS-standard config layout."""
from __future__ import annotations

from ssh_manager.platforms.macos import MacOS
from ssh_manager.util.paths import resolve_config_dir, resolve_paths


def test_default_is_xdg_config_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)   # default base = ~/.config
    cwd = tmp_path / "anywhere"
    assert resolve_config_dir(MacOS(), env={}, cwd=cwd) == tmp_path / ".config" / "ssh-manager"


def test_xdg_config_home_respected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    # XDG_CONFIG_HOME is honored - and read from the SAME env mapping as the override,
    # so a programmatic caller's env dict resolves consistently (not split with os.environ).
    assert resolve_config_dir(
        MacOS(), env={"XDG_CONFIG_HOME": str(tmp_path / "xdg")}, cwd=tmp_path
    ) == tmp_path / "xdg" / "ssh-manager"
    # an env dict WITHOUT XDG falls back to ~/.config even if the process env has one
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "should-be-ignored"))
    assert resolve_config_dir(MacOS(), env={}, cwd=tmp_path) == tmp_path / ".config" / "ssh-manager"


def test_ssh_manager_home_override_and_alias(tmp_path) -> None:
    assert resolve_config_dir(
        MacOS(), env={"SSH_MANAGER_HOME": str(tmp_path / "h")}, cwd=tmp_path) == tmp_path / "h"
    # SSH_MANAGER_CONFIG_DIR is an accepted alias of SSH_MANAGER_HOME
    assert resolve_config_dir(
        MacOS(), env={"SSH_MANAGER_CONFIG_DIR": str(tmp_path / "h2")},
        cwd=tmp_path) == tmp_path / "h2"


def test_no_project_local_mode_always_home(tmp_path, monkeypatch) -> None:
    # even with a ./config/manifest.json present, the home is the standard config
    # dir - there is no project-local mode, one home inside a checkout or not.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "manifest.json").write_text("{}")
    assert resolve_config_dir(MacOS(), env={}, cwd=tmp_path) == tmp_path / ".config" / "ssh-manager"


def test_paths_layout(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".sshmgr"
    p = resolve_paths(MacOS(), env={"SSH_MANAGER_HOME": str(home)},
                      cwd=tmp_path / "x", ssh_dir=tmp_path / ".ssh")
    assert p.config_dir == home and p.home == home
    assert p.manifest == home / "manifest.json"
    assert p.providers == home / "providers.json"
    assert p.env_file == home / ".env"                 # secrets in the home
    assert p.audit_log == home / "log" / "audit.log"   # logs under log/
    assert p.snapshots_dir == home / "snapshots"
    assert p.lock_file == home / ".state" / ".lock"    # transient state under .state/
    assert p.expiry_cache == home / ".state" / "expiry-cache.json"


def test_env_always_in_home(tmp_path, monkeypatch) -> None:
    # .env always lives in the home (no repo-root convention anymore)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    p = resolve_paths(MacOS(), env={}, cwd=tmp_path, ssh_dir=tmp_path / ".ssh")
    home = tmp_path / ".config" / "ssh-manager"
    assert p.config_dir == home
    assert p.env_file == home / ".env"


def test_override_named_config_keeps_env_in_home(tmp_path) -> None:
    # H1: an explicit override is authoritative even if the home is named
    # "config" under cwd - .env stays IN the home, not the parent.
    home = tmp_path / "config"
    p = resolve_paths(MacOS(), env={"SSH_MANAGER_HOME": str(home)},
                      cwd=tmp_path, ssh_dir=tmp_path / ".ssh")
    assert p.config_dir == home
    assert p.env_file == home / ".env"                 # NOT tmp_path/.env


def test_relative_override_is_absolutized(tmp_path) -> None:
    # H2: a relative override resolves against cwd and .env lands in the home.
    p = resolve_paths(MacOS(), env={"SSH_MANAGER_HOME": "myhome"},
                      cwd=tmp_path, ssh_dir=tmp_path / ".ssh")
    assert p.config_dir == tmp_path / "myhome"
    assert p.env_file == tmp_path / "myhome" / ".env"


def test_legacy_dot_sshmgr_is_migrated(tmp_path, monkeypatch) -> None:
    # On first run with no override, a legacy ~/.sshmgr is moved to the standard dir.
    from ssh_manager.platforms.macos import MacOS as _MacOS
    from ssh_manager.services.facade import SshManagerService
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("SSH_MANAGER_HOME", raising=False)
    monkeypatch.delenv("SSH_MANAGER_CONFIG_DIR", raising=False)
    legacy = tmp_path / ".sshmgr"
    legacy.mkdir()
    (legacy / "manifest.json").write_text('{"version": 1, "profiles": {}}')
    svc = SshManagerService(platform=_MacOS(), ssh_dir=tmp_path / ".ssh")
    new = tmp_path / ".config" / "ssh-manager"
    assert svc.paths.config_dir == new
    assert new.is_dir() and (new / "manifest.json").exists()   # contents moved
    assert not legacy.exists()                                  # legacy gone


def test_migration_never_nests_when_new_home_exists(tmp_path, monkeypatch) -> None:
    # If BOTH the legacy and the standard home exist, migration must NOT move the
    # legacy dir INSIDE the new one (the TOCTOU/nesting bug) - the new home wins and
    # the legacy is left intact for the user to reconcile.
    from ssh_manager.platforms.macos import MacOS as _MacOS
    from ssh_manager.services.facade import SshManagerService
    monkeypatch.setenv("HOME", str(tmp_path))
    for v in ("XDG_CONFIG_HOME", "SSH_MANAGER_HOME", "SSH_MANAGER_CONFIG_DIR"):
        monkeypatch.delenv(v, raising=False)
    legacy = tmp_path / ".sshmgr"
    legacy.mkdir()
    (legacy / "manifest.json").write_text('{"version": 1, "profiles": {}}')
    new = tmp_path / ".config" / "ssh-manager"
    new.mkdir(parents=True)
    (new / "manifest.json").write_text('{"version": 1, "profiles": {}}')
    SshManagerService(platform=_MacOS(), ssh_dir=tmp_path / ".ssh")
    assert not (new / ".sshmgr").exists()      # never nested inside the new home
    assert legacy.is_dir()                      # legacy untouched (new pre-existed)
    assert (new / "manifest.json").exists()     # new home intact


def test_migrate_force_backs_up_then_replaces(tmp_path, monkeypatch) -> None:
    # The stranded both-exist case: `sshmgr migrate --force` backs up the current
    # home and replaces it with the legacy one (legacy data wins, nothing lost).
    import pytest

    from ssh_manager.platforms.macos import MacOS as _MacOS
    from ssh_manager.services.facade import SshManagerService
    from ssh_manager.util.errors import SshManagerError
    monkeypatch.setenv("HOME", str(tmp_path))
    for v in ("XDG_CONFIG_HOME", "SSH_MANAGER_HOME", "SSH_MANAGER_CONFIG_DIR"):
        monkeypatch.delenv(v, raising=False)
    legacy = tmp_path / ".sshmgr"
    legacy.mkdir()
    (legacy / "manifest.json").write_text('{"version": 1, "profiles": {}}')
    home = tmp_path / ".config" / "ssh-manager"
    home.mkdir(parents=True)
    (home / "marker").write_text("old-standard")
    # constructing the service must NOT auto-migrate when both already exist
    svc = SshManagerService(platform=_MacOS(), ssh_dir=tmp_path / ".ssh")
    assert legacy.is_dir() and (home / "marker").exists()
    with pytest.raises(SshManagerError, match="both"):
        svc.migrate_home()                          # refuses without --force
    res = svc.migrate_home(force=True)
    assert res.moved and res.backup is not None and res.backup.is_dir()
    assert (home / "manifest.json").exists()        # legacy content now at the home
    assert not (home / "marker").exists()           # old standard home moved aside
    assert (res.backup / "marker").exists()         # ... into the backup
    assert not legacy.exists()


def test_empty_override_falls_through(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    cwd = tmp_path / "nowhere"
    assert resolve_config_dir(
        MacOS(), env={"SSH_MANAGER_HOME": ""}, cwd=cwd) == tmp_path / ".config" / "ssh-manager"
