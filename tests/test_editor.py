"""profile/host CRUD + delete-revoke/prune + orphan detection."""
from __future__ import annotations

import pytest

from ssh_manager.providers.base import DeployOutcome
from ssh_manager.providers.ssh_generic import GenericSSH
from ssh_manager.services.facade import SshManagerService
from ssh_manager.util.errors import SshManagerError


def test_profile_add_edit_delete(svc: SshManagerService) -> None:
    svc.profile_add("staging", key_scope="shared", key_name="staging_all-ed25519")
    m = svc.manifest()
    assert m.profiles["staging"].key_scope == "shared"
    svc.profile_edit("staging", key_scope="per_service")
    assert svc.manifest().profiles["staging"].key_scope == "per_service"
    with pytest.raises(SshManagerError, match="already exists"):
        svc.profile_add("staging")
    svc.profile_delete("staging", revoke=False)
    assert "staging" not in svc.manifest().profiles


def test_host_add_then_reconcile_mints_it(svc: SshManagerService) -> None:
    svc.profile_add("ops")
    svc.host_add("ops", "bastion", hostname="10.0.0.9", user="admin", port=2222,
                 provider="generic-ssh", tags=["prod"])
    host = svc.manifest().profiles["ops"].hosts[0]
    assert host.hostname == "10.0.0.9" and host.port == 2222 and host.tags == ["prod"]
    svc.reconcile()
    assert (svc.paths.ssh_dir / "profiles/ops/ops_bastion-ed25519").exists()


def test_host_edit_updates_fields(svc: SshManagerService) -> None:
    svc.host_edit("work", "unc", user="newuser", port=2200)
    host = svc.manifest().profiles["work"].hosts[0]
    assert host.user == "newuser" and host.port == 2200
    assert host.hostname == "sc.its.unc.edu"     # untouched fields preserved


def test_host_delete_revokes_and_prunes(svc: SshManagerService, monkeypatch) -> None:
    removed: list = []
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr(GenericSSH, "remove", lambda self, t: removed.append(t.alias) or True)
    svc.reconcile()
    svc.deploy("work_unc-ed25519")              # now has a deployment
    res = svc.host_delete("work", "unc", revoke=True)
    assert "unc" in res.revoked
    assert "work_unc-ed25519" in res.pruned_keys
    assert not svc.manifest().profiles["work"].hosts        # host gone
    # inventory entry pruned
    assert not any(r.path.endswith("work_unc-ed25519") for r in svc.inventory().keys.values())


def test_doctor_flags_orphaned_key_after_delete(svc: SshManagerService) -> None:
    svc.reconcile()                              # mints work_unc-ed25519 on disk
    svc.host_delete("work", "unc", revoke=False)  # remove from manifest; key file stays
    report = svc.doctor()
    assert any("work_unc-ed25519" in o for o in report.orphan_keys)


def test_doctor_flags_duplicate_fingerprints(svc: SshManagerService) -> None:
    svc.reconcile()
    ssh = svc.paths.ssh_dir
    # copy one key's material onto another -> same fingerprint (reuse)
    src = ssh / "profiles/personal/personal_github-ed25519"
    dst = ssh / "profiles/simtabi/simtabi_github-ed25519"
    dst.write_bytes(src.read_bytes())
    dst.with_suffix(".pub").write_bytes(src.with_suffix(".pub").read_bytes())
    assert svc.doctor().duplicate_keys      # reported


def test_doctor_ignores_config_and_os_cruft(svc: SshManagerService) -> None:
    """Regression (real-run): per-profile `config` files and macOS `.DS_Store`
    must not be flagged as orphaned keys or perm issues."""
    svc.reconcile()
    (svc.paths.ssh_dir / "profiles/.DS_Store").write_text("x")
    (svc.paths.ssh_dir / "profiles/work/.DS_Store").write_text("x")
    rep = svc.doctor()
    assert rep.orphan_keys == []                                  # config is not a key
    assert not any(".DS_Store" in p for p in rep.perm_issues)     # cruft not managed
    assert rep.ok


def test_unknown_targets_error(svc: SshManagerService) -> None:
    with pytest.raises(SshManagerError, match="unknown profile"):
        svc.host_add("nope", "x", hostname="h", user="u")
    with pytest.raises(SshManagerError, match="unknown host"):
        svc.host_edit("work", "ghost", user="z")
