"""Clean-state + snapshot/backup safety model (the mutation guard)."""
from __future__ import annotations

import stat
from pathlib import Path

from ssh_manager.services.facade import SshManagerService
from ssh_manager.util import fs


def test_clean_temp_artifacts_sweeps_crash_residue(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    (ssh / "profiles/work").mkdir(parents=True)
    stale = ssh / "profiles/work" / ".config.abcd.tmp"
    stale.write_text("half-written")
    keep = ssh / "profiles/work" / "config"
    keep.write_text("real")
    staging = ssh / "profiles/work" / ".staging"   # crash residue from a dead rotation
    staging.mkdir()
    (staging / "work_x-ed25519").write_text("staged")
    removed = fs.clean_temp_artifacts(ssh)
    assert "profiles/work/.config.abcd.tmp" in removed
    assert "profiles/work/.staging" in removed
    assert not stale.exists()
    assert not staging.exists()
    assert keep.exists()        # only our temp prefix + .staging are swept


def test_every_mutating_verb_snapshots(svc: SshManagerService) -> None:
    svc.reconcile()             # builds the tree (no snapshot: ~/.ssh didn't exist)
    assert svc.list_snapshots() == []
    svc.config_render()         # mutating verb -> snapshots the now-existing tree
    assert len(svc.list_snapshots()) == 1


def test_snapshot_filenames_are_unique(svc: SshManagerService) -> None:
    svc.reconcile()
    # two snapshots in quick succession must not clobber each other
    a = fs.snapshot_ssh_dir(svc.paths.ssh_dir, svc.paths.snapshots_dir, stamp="20260603-120000")
    b = fs.snapshot_ssh_dir(svc.paths.ssh_dir, svc.paths.snapshots_dir, stamp="20260603-120000")
    assert a is not None and b is not None and a != b
    assert a.exists() and b.exists()
    assert stat.S_IMODE(b.stat().st_mode) == 0o600   # contains private keys


def test_restore_snapshot_brings_back_deleted_files(svc: SshManagerService) -> None:
    svc.reconcile()
    svc.config_render()         # snapshot #1 with keys + config
    key = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    original = key.read_bytes()
    key.unlink()
    (svc.paths.ssh_dir / "profiles/work/config").unlink()
    chosen = svc.restore_snapshot()      # restores latest; snapshots current first
    assert key.exists()
    assert key.read_bytes() == original
    assert (svc.paths.ssh_dir / "profiles/work/config").exists()
    assert chosen.exists()
    # restore is itself reversible: it snapshotted the (broken) current tree too
    assert len(svc.list_snapshots()) >= 2


def test_prune_snapshots_keeps_latest(svc: SshManagerService) -> None:
    svc.reconcile()
    for i in range(4):
        fs.snapshot_ssh_dir(svc.paths.ssh_dir, svc.paths.snapshots_dir,
                            stamp=f"20260603-12000{i}")
    removed = svc.prune_snapshots(keep=2)
    assert removed == 2
    assert len(svc.list_snapshots()) == 2


def test_reconcile_does_not_chmod_unrelated_ssh_files(svc: SshManagerService) -> None:
    ssh = svc.paths.ssh_dir
    ssh.mkdir(parents=True)
    stray = ssh / "id_rsa"            # a user's own key, not tool-managed
    stray.write_text("PRIVATE")
    stray.chmod(0o644)
    kh = ssh / "known_hosts"
    kh.write_text("host ssh-ed25519 AAAA")
    kh.chmod(0o644)
    svc.reconcile()
    # untouched: perm enforcement is scoped to tool-managed paths only
    assert stat.S_IMODE(stray.stat().st_mode) == 0o644
    assert stat.S_IMODE(kh.stat().st_mode) == 0o644
    assert not any("id_rsa" in i or "known_hosts" in i for i in svc.doctor().perm_issues)
