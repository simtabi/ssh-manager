"""keygen (targeted mint) + audit summary."""
from __future__ import annotations

import pytest

from ssh_manager.services.facade import SshManagerService
from ssh_manager.util.errors import SshManagerError


def test_keygen_mints_only_the_selector(svc: SshManagerService) -> None:
    minted = svc.keygen("work")
    assert [m.key_name for m in minted] == ["work_unc-ed25519"]
    ssh = svc.paths.ssh_dir
    assert (ssh / "profiles/work/work_unc-ed25519").exists()
    # other profiles untouched (no phantom full reconcile)
    assert not (ssh / "profiles/personal").exists()
    # idempotent: second keygen mints nothing
    assert svc.keygen("work") == []


def test_keygen_by_host_alias(svc: SshManagerService) -> None:
    minted = svc.keygen("oribi-web")
    assert [m.key_name for m in minted] == ["development_oribi-web-ed25519"]


def test_keygen_unknown_selector_errors(svc: SshManagerService) -> None:
    with pytest.raises(SshManagerError, match="unknown profile or host"):
        svc.keygen("does-not-exist")


def test_keygen_with_passphrase(svc: SshManagerService) -> None:
    import subprocess
    svc.keygen("work", passphrase="s3cret")
    key = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    # the empty passphrase must NOT unlock it; the real one must
    assert subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)],
                          capture_output=True).returncode != 0
    assert subprocess.run(["ssh-keygen", "-y", "-P", "s3cret", "-f", str(key)],
                          capture_output=True).returncode == 0


def test_load_adds_profile_keys_to_agent(svc: SshManagerService, monkeypatch) -> None:
    svc.reconcile()
    calls: list = []
    monkeypatch.setattr("ssh_manager.services.agent.proc.require", lambda *a, **k: "/x")
    monkeypatch.setattr(
        "ssh_manager.services.agent.proc.run_interactive", lambda c, **k: calls.append(c) or 0
    )
    added = svc.load("development")
    assert added == ["development_oribi-web-ed25519"]
    assert len(calls) == 1
    # macOS platform -> keychain flag is passed
    assert any("--apple-use-keychain" in c for c in calls)


def test_load_shared_profile_adds_key_once(svc: SshManagerService, monkeypatch) -> None:
    svc.reconcile()
    calls: list = []
    monkeypatch.setattr("ssh_manager.services.agent.proc.require", lambda *a, **k: "/x")
    monkeypatch.setattr(
        "ssh_manager.services.agent.proc.run_interactive", lambda c, **k: calls.append(c) or 0
    )
    added = svc.load("shared-demo")     # 2 hosts, one shared key -> added once
    assert added == ["shareddemo_all-ed25519"]
    assert len(calls) == 1


def test_audit_reports_deployments(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.require", lambda *a, **k: "/x")
    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.run_interactive", lambda c, **k: 0)
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    svc.reconcile()
    svc.deploy("work_unc-ed25519")
    out = svc.audit()
    assert "=== deployments ===" in out
    assert "unc via ssh-copy-id (verified)" in out
    assert "=== recent activity ===" in out
    assert "deploy" in out          # audit log line
