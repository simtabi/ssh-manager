"""deploy: providers, inventory recording, idempotency, degrade-to-manual."""
from __future__ import annotations

import pytest

from ssh_manager.services.facade import SshManagerService


@pytest.fixture
def fake_copy_id(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Stub ssh-copy-id (and require) so generic-ssh deploy succeeds offline."""
    calls: dict[str, list] = {"interactive": []}
    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.require", lambda *a, **k: "/x")
    monkeypatch.setattr(
        "ssh_manager.providers.ssh_generic.proc.run_interactive",
        lambda cmd, **k: calls["interactive"].append(cmd) or 0,
    )
    # the deployer prechecks reachability; treat the host as reachable offline
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    return calls


def test_generic_ssh_deploy_records_verified(svc: SshManagerService, fake_copy_id) -> None:
    svc.reconcile()
    report = svc.deploy("work_unc-ed25519")          # work/unc -> generic ssh
    assert report.records[0].method == "ssh-copy-id"
    assert report.records[0].verified
    # the ssh-copy-id command targeted the right host + key + port
    cmd = " ".join(fake_copy_id["interactive"][0])
    assert "ssh-copy-id" in cmd and "uncgit@sc.its.unc.edu" in cmd and "-p 443" in cmd
    # inventory records the deployment as verified, keyed by fingerprint
    inv = svc.inventory()
    rec = next(r for r in inv.keys.values() if r.path.endswith("work_unc-ed25519"))
    assert not rec.needs_redeploy
    assert rec.deployments[0].target == "unc" and rec.deployments[0].verified


def test_deploy_is_idempotent_one_entry_per_target(svc: SshManagerService, fake_copy_id) -> None:
    svc.reconcile()
    svc.deploy("work_unc-ed25519")
    svc.deploy("work_unc-ed25519")                   # twice
    inv = svc.inventory()
    rec = next(r for r in inv.keys.values() if r.path.endswith("work_unc-ed25519"))
    assert len([d for d in rec.deployments if d.target == "unc"]) == 1


def test_github_degrades_to_manual_without_token(svc: SshManagerService, monkeypatch) -> None:
    svc.reconcile()
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr("ssh_manager.providers.github.proc.has", lambda b: False)
    report = svc.deploy("personal_github-ed25519")   # github provider, no token
    assert report.records[0].method == "manual"
    assert not report.records[0].verified
    assert "github.com/settings/keys" in report.records[0].detail
    inv = svc.inventory()
    rec = next(r for r in inv.keys.values() if r.path.endswith("personal_github-ed25519"))
    assert rec.needs_redeploy            # manual -> still needs confirmation


def test_deploy_requires_minted_key(svc: SshManagerService) -> None:
    from ssh_manager.util.errors import SshManagerError
    with pytest.raises(SshManagerError, match="run `sshmgr reconcile`"):
        svc.deploy("work_unc-ed25519")   # not reconciled yet


def test_deploy_unknown_key_errors(svc: SshManagerService) -> None:
    from ssh_manager.util.errors import SshManagerError
    svc.reconcile()
    with pytest.raises(SshManagerError, match="no host"):
        svc.deploy("nope_x-ed25519")


def test_shared_key_deploys_to_all_hosts(svc: SshManagerService, fake_copy_id) -> None:
    svc.reconcile()
    report = svc.deploy("shareddemo_all-ed25519")    # shared scope -> box-a + box-b
    targets = {r.target for r in report.records}
    assert targets == {"box-a", "box-b"}


# (generic-ssh remove safety rails are covered in test_ssh_generic.py)
