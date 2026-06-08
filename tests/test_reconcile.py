"""Integration tests for reconcile: minting, perms, idempotency, drift, security.

These shell out to ssh-keygen (a hard dep, present in CI) against a temp HOME.
"""
from __future__ import annotations

import stat
from pathlib import Path

from ssh_manager.services.facade import SshManagerService


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_reconcile_mints_keys_and_renders_config(svc: SshManagerService) -> None:
    res = svc.reconcile()
    ssh = svc.paths.ssh_dir
    # 5 distinct keys minted (work, personal, simtabi, development, shared-demo);
    # school is empty.
    assert len(res.minted) == 5
    assert (ssh / "config").exists()
    assert (ssh / "profiles/work/work_unc-ed25519").exists()
    assert (ssh / "profiles/work/work_unc-ed25519.pub").exists()
    assert not (ssh / "profiles/school").exists()
    # Minted keys are flagged needs-redeploy in the inventory.
    inv = svc.inventory()
    assert inv.keys, "inventory should be populated"
    assert all(rec.needs_redeploy for rec in inv.keys.values())


def test_reconcile_is_idempotent_and_non_destructive(svc: SshManagerService) -> None:
    svc.reconcile()
    priv = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    first = priv.read_bytes()
    second = svc.reconcile()
    assert second.minted == []            # nothing re-minted
    assert priv.read_bytes() == first      # existing private key never clobbered
    assert svc.config_check().in_sync      # config stays in sync


def test_perms_are_load_bearing(svc: SshManagerService) -> None:
    svc.reconcile()
    ssh = svc.paths.ssh_dir
    assert _mode(ssh) == 0o700
    assert _mode(ssh / "config") == 0o600
    assert _mode(ssh / "profiles/work/work_unc-ed25519") == 0o600
    assert _mode(ssh / "profiles/work/work_unc-ed25519.pub") == 0o644
    assert _mode(ssh / "profiles/work") == 0o700


def test_config_check_detects_drift_and_render_fixes(svc: SshManagerService) -> None:
    svc.reconcile()
    cfg = svc.paths.ssh_dir / "profiles/work/config"
    cfg.write_text(cfg.read_text() + "\n# sneaky hand edit\n")
    assert not svc.config_check().in_sync           # drift detected
    svc.config_render()                              # the fixer
    assert svc.config_check().in_sync                # back in sync


def test_dry_run_writes_nothing(svc: SshManagerService) -> None:
    res = svc.reconcile(dry_run=True)
    assert res.dry_run
    assert not (svc.paths.ssh_dir / "config").exists()  # nothing written
    assert len(res.minted) == 5                          # but it reports the plan


def test_two_github_identities_dont_cross_offer(svc: SshManagerService) -> None:
    svc.reconcile()
    personal = (svc.paths.ssh_dir / "profiles/personal/config").read_text()
    simtabi = (svc.paths.ssh_dir / "profiles/simtabi/config").read_text()
    assert "personal_github-ed25519" in personal
    assert "simtabi_github-ed25519" not in personal     # no cross-offer
    assert "simtabi_github-ed25519" in simtabi


def test_doctor_clean_after_reconcile(svc: SshManagerService) -> None:
    svc.reconcile()
    report = svc.doctor()
    assert not report.perm_issues
    assert report.config_in_sync
    assert all(n <= 1 for n in report.old_keys.values())
