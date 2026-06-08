"""Rotation + rollback: staged, single-old-archive, zero-downtime."""
from __future__ import annotations

import pytest

from ssh_manager.providers.base import DeployOutcome
from ssh_manager.providers.ssh_generic import GenericSSH
from ssh_manager.services.facade import SshManagerService
from ssh_manager.util.errors import SshManagerError

KEY = "work_unc-ed25519"


def _mock_generic(monkeypatch, *, verify: bool = True, deploy_manual: bool = False) -> dict:
    """Make the generic-ssh provider act offline; record calls."""
    calls: dict[str, list] = {"deploy": [], "verify": [], "remove": []}

    def deploy(self, t):
        calls["deploy"].append(t.alias)
        method = "manual" if deploy_manual else "ssh-copy-id"
        return DeployOutcome(method, verified=not deploy_manual)

    monkeypatch.setattr(GenericSSH, "deploy", deploy)
    monkeypatch.setattr(GenericSSH, "verify",
                        lambda self, t: calls["verify"].append(t.alias) or verify)
    monkeypatch.setattr(GenericSSH, "remove",
                        lambda self, t: calls["remove"].append(t.alias) or True)
    # rotate/rollback precheck reachability; treat the host as reachable offline
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    return calls


def test_rotate_commits_archives_and_resets(svc: SshManagerService, monkeypatch) -> None:
    _mock_generic(monkeypatch)
    svc.reconcile()
    ssh = svc.paths.ssh_dir
    before = (ssh / "profiles/work" / KEY).read_bytes()

    report = svc.rotate(KEY)
    assert report.committed
    assert report.old_fingerprint != report.new_fingerprint
    # current key replaced (new material), staging gone, predecessor archived
    assert (ssh / "profiles/work" / KEY).read_bytes() != before
    assert not (ssh / "profiles/work/.staging").exists()
    assert (ssh / "profiles/work/old" / KEY).exists()
    assert (ssh / "profiles/work/old" / f"{KEY}.pub").exists()
    # inventory: new fp at canonical path (deployed+verified), old fp archived
    inv = svc.inventory()
    assert report.new_fingerprint in inv.keys
    assert inv.keys[report.new_fingerprint].path.endswith(f"work/{KEY}")
    assert not inv.keys[report.new_fingerprint].needs_redeploy
    assert "/old/" in inv.keys[report.old_fingerprint].path
    # archived predecessor is excluded from expiry
    assert report.old_fingerprint not in {s.fingerprint for s in svc.expiry_states()}


def test_rotate_enforces_single_old(svc: SshManagerService, monkeypatch) -> None:
    _mock_generic(monkeypatch)
    svc.reconcile()
    svc.rotate(KEY)
    svc.rotate(KEY)                     # rotate again
    old_dir = svc.paths.ssh_dir / "profiles/work/old"
    privs = [p for p in old_dir.iterdir() if not p.name.endswith(".pub")]
    assert privs == [old_dir / KEY]     # exactly one predecessor kept
    assert svc.doctor().old_keys.get(KEY) == 1
    assert svc.doctor().ok or svc.doctor().perm_issues  # ≤1-old never trips


def test_rotate_aborts_on_verify_failure(svc: SshManagerService, monkeypatch) -> None:
    _mock_generic(monkeypatch, verify=False)
    svc.reconcile()
    ssh = svc.paths.ssh_dir
    before = (ssh / "profiles/work" / KEY).read_bytes()
    report = svc.rotate(KEY)
    assert not report.committed
    # zero-downtime: active key + files untouched, no /old/, staging discarded
    assert (ssh / "profiles/work" / KEY).read_bytes() == before
    assert not (ssh / "profiles/work/old").exists()
    assert not (ssh / "profiles/work/.staging").exists()


def test_rotate_abort_pulls_staged_key_back_off_targets(
        svc: SshManagerService, monkeypatch) -> None:
    """Partial-deploy rollback: when verify fails after the staged key already landed
    on a target, the abort path must REMOVE the staged key from that target so an
    aborted rotation doesn't leave an orphan key in authorized_keys / the account."""
    calls = _mock_generic(monkeypatch, verify=False)   # deploy lands, verify fails
    svc.reconcile()
    report = svc.rotate(KEY)
    assert not report.committed
    # the staged key was deployed to the target, then pulled back off it on abort
    assert calls["deploy"] == ["unc"]
    assert calls["remove"] == ["unc"], "aborted rotation must revoke the staged key it deployed"


def test_rotate_allow_unverified_commits(svc: SshManagerService, monkeypatch) -> None:
    _mock_generic(monkeypatch, verify=False)
    svc.reconcile()
    report = svc.rotate(KEY, allow_unverified=True)
    assert report.committed


def test_rollback_restores_predecessor(svc: SshManagerService, monkeypatch) -> None:
    _mock_generic(monkeypatch)
    svc.reconcile()
    ssh = svc.paths.ssh_dir
    original = (ssh / "profiles/work" / KEY).read_bytes()
    rot = svc.rotate(KEY)
    assert (ssh / "profiles/work" / KEY).read_bytes() != original
    back = svc.rollback(KEY)
    assert back.committed
    # the original key material is restored to the canonical path
    assert (ssh / "profiles/work" / KEY).read_bytes() == original
    assert back.new_fingerprint == rot.old_fingerprint
    # the rotated-in key's record is gone; restored key is at canonical path
    inv = svc.inventory()
    assert rot.new_fingerprint not in inv.keys
    assert inv.keys[rot.old_fingerprint].path.endswith(f"work/{KEY}")


def test_allow_unverified_commits_manual_target(svc: SshManagerService) -> None:
    # development/oribi-web uses the ploi provider -> manual deploy, can't verify.
    svc.reconcile()
    key = "development_oribi-web-ed25519"
    aborted = svc.rotate(key)                       # default: manual can't verify -> abort
    assert not aborted.committed
    done = svc.rotate(key, allow_unverified=True)   # override accepts manual targets
    assert done.committed
    assert (svc.paths.ssh_dir / f"profiles/development/old/{key}").exists()


def test_rotate_unknown_key_errors(svc: SshManagerService) -> None:
    svc.reconcile()
    with pytest.raises(SshManagerError, match="no host"):
        svc.rotate("nope_x-ed25519")


def test_rollback_without_predecessor_errors(svc: SshManagerService) -> None:
    svc.reconcile()
    with pytest.raises(SshManagerError, match="no /old/ predecessor"):
        svc.rollback(KEY)
