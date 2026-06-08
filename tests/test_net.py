"""Network reachability + VPN-aware status (and the deploy precheck)."""
from __future__ import annotations

import subprocess

from ssh_manager.services.facade import SshManagerService
from ssh_manager.util import net


def test_tcp_reachable_false_on_closed_port() -> None:
    # 127.0.0.1:1 is reliably closed; must fail fast, not hang.
    assert net.tcp_reachable("127.0.0.1", 1, timeout=2.0) is False


def test_netstatus_message_vpn_aware() -> None:
    s = net.NetStatus("sc.its.unc.edu", 443, reachable=False, requires_vpn=True,
                      vpn_name="UNC VPN", vpn_url="https://vpn.unc.edu", vpn=False)
    msg = s.message
    assert "requires a VPN" in msg and "UNC VPN" in msg and "connect it" in msg
    assert "https://vpn.unc.edu" in msg          # the connection URL is surfaced
    ok = net.NetStatus("github.com", 22, reachable=True)
    assert ok.message.endswith("reachable")


def test_ssh_reachable_detects_hang_and_refusal(monkeypatch) -> None:
    # a wedged banner shows up as our timeout marker -> unreachable
    def hung(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 124, stdout="", stderr="timed out after 15s")
    monkeypatch.setattr("ssh_manager.util.proc.has", lambda b: True)
    monkeypatch.setattr("ssh_manager.util.proc.run", hung)
    assert net.ssh_reachable("sc.its.unc.edu", 443, timeout=10) is False

    def refused(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="Connection refused")
    monkeypatch.setattr("ssh_manager.util.proc.run", refused)
    assert net.ssh_reachable("host", 22) is False

    def authfail(cmd, **kw):   # server answered (banner ok), auth just failed -> reachable
        return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="Permission denied")
    monkeypatch.setattr("ssh_manager.util.proc.run", authfail)
    assert net.ssh_reachable("github.com", 22) is True


def test_network_status_flags_vpn_host(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: False)
    rows = svc.network_status("unc")
    assert rows and rows[0].alias == "unc"
    assert rows[0].status.requires_vpn is True
    assert "requires a VPN" in rows[0].status.message


def test_deploy_precheck_skips_unreachable_host(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: False)
    svc.reconcile()
    report = svc.deploy("work_unc-ed25519")          # unc is unreachable in this test
    rec = report.records[0]
    assert rec.method == "unreachable" and not rec.verified
    assert "requires a VPN" in rec.detail            # actionable, no hang
