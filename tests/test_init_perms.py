"""Tests for `sshmgr init` and the perms auto-fix (doctor --fix / fix_perms)."""
from __future__ import annotations

import stat
from pathlib import Path

from ssh_manager.platforms.macos import MacOS
from ssh_manager.services.facade import SshManagerService


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_init_creates_starter_with_secret_perms(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    config_dir = tmp_path / "config"          # does not exist yet
    svc = SshManagerService(
        env={"SSH_MANAGER_CONFIG_DIR": str(config_dir)}, ssh_dir=home / ".ssh", platform=MacOS(),
    )
    res = svc.init()
    assert set(res.created) >= {"manifest.json", "inventory.json", ".env"}
    assert _mode(config_dir / ".env") == 0o600          # secret born 0600
    assert _mode(config_dir) == 0o700
    assert svc.manifest().version == 1                   # starter loads + validates
    # idempotent: second run creates nothing, never overwrites
    res2 = svc.init()
    assert res2.created == []
    assert ".env" in res2.existed


def _svc(tmp_path: Path, monkeypatch) -> SshManagerService:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return SshManagerService(env={"SSH_MANAGER_CONFIG_DIR": str(tmp_path / "cfg")},
                         ssh_dir=home / ".ssh", platform=MacOS())


def test_init_force_overwrites_without_backup_by_default(tmp_path: Path, monkeypatch) -> None:
    svc = _svc(tmp_path, monkeypatch)
    svc.init()
    cfg = svc.paths.config_dir
    (cfg / "manifest.json").write_text('{"version": 1, "profiles": {"mine": {"hosts": []}}}')

    res = svc.init(force=True)                             # no --backup
    assert "mine" not in (cfg / "manifest.json").read_text()   # reset to default
    assert res.backup is None                                  # nothing kept
    assert not list((cfg / ".state").glob("init-backup-*"))    # no backup dir created
    assert _mode(cfg / ".env") == 0o600


def test_init_force_with_backup_keeps_old(tmp_path: Path, monkeypatch) -> None:
    svc = _svc(tmp_path, monkeypatch)
    svc.init()
    cfg = svc.paths.config_dir
    (cfg / "manifest.json").write_text('{"version": 1, "profiles": {"mine": {"hosts": []}}}')
    (cfg / ".env").write_text("GH_TOKEN=mysecret\n")

    res = svc.init(force=True, backup=True)
    assert "mine" not in (cfg / "manifest.json").read_text()   # reset...
    assert res.backup is not None and res.backup.exists()      # ...but backed up
    assert "mine" in (res.backup / "manifest.json").read_text()
    assert "mysecret" in (res.backup / ".env").read_text()


def test_fix_perms_repairs_loosened_key_and_secret(svc: SshManagerService) -> None:
    svc.reconcile()
    key = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    key.chmod(0o644)                                     # loosened private key
    env = svc.paths.env_file
    env.write_text("GH_TOKEN=secret")
    env.chmod(0o666)                                     # world-writable secret
    changed = svc.fix_perms()
    assert _mode(key) == 0o600
    assert _mode(env) == 0o600
    assert any("work_unc-ed25519" in c for c in changed)
    assert any(".env" in c for c in changed)
    # and now doctor is clean
    assert not svc.doctor().perm_issues
