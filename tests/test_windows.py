"""Windows platform: icacls ACLs, schtasks scheduler, PowerShell toast.

The mocked unit tests run everywhere; the ``win32_only`` integration tests run the
real ``icacls``/``schtasks`` binaries and so only execute on a Windows runner (CI's
windows-latest job) - that's where the platform code is actually validated.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ssh_manager.platforms.windows import Windows, _ps_str

win32_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only integration")


class _Resp:
    returncode = 0
    stdout = ""
    stderr = ""


def _patch(monkeypatch, calls):
    monkeypatch.setattr("ssh_manager.platforms.windows.proc.require", lambda *a, **k: "/x")
    monkeypatch.setattr("ssh_manager.platforms.windows.proc.has", lambda b: True)
    monkeypatch.setattr("ssh_manager.platforms.windows.proc.run",
                        lambda c, **k: calls.append(c) or _Resp())
    monkeypatch.setattr("ssh_manager.platforms.windows.proc.run_checked",
                        lambda c, **k: calls.append(c) or _Resp())


def test_set_perms_restricts_to_current_user(monkeypatch) -> None:
    monkeypatch.setenv("USERNAME", "alice")
    calls: list[list[str]] = []
    _patch(monkeypatch, calls)
    Windows().set_perms(Path("C:/Users/alice/.ssh/id"), 0o600)
    assert any("/inheritance:r" in c for c in calls)          # drop inherited ACEs
    assert any(c[-1] == "alice:F" for c in calls)             # grant only this user


def test_install_scheduler_creates_daily_task(monkeypatch) -> None:
    calls: list[list[str]] = []
    _patch(monkeypatch, calls)
    Windows().install_scheduler("sshmgr audit --notify")
    task = calls[-1]
    assert task[:4] == ["schtasks", "/Create", "/TN", "ssh_manager.expiry"]
    assert "/SC" in task and "DAILY" in task and "sshmgr audit --notify" in task


def test_notify_builds_escaped_powershell_toast(monkeypatch) -> None:
    calls: list[list[str]] = []
    _patch(monkeypatch, calls)
    Windows().notify("sshmgr", "key 'x' is due")
    cmd = calls[-1]
    assert cmd[:3] == ["powershell", "-NoProfile", "-Command"]
    assert "ShowBalloonTip" in cmd[-1]
    assert "'key ''x'' is due'" in cmd[-1]                    # single quotes doubled


def test_ps_str_escaping() -> None:
    assert _ps_str("a'b") == "'a''b'"


def test_paths_fall_back_off_windows(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    win = Windows()
    assert win.ssh_dir().name == ".ssh"                       # no KeyError off-Windows
    # config home is the single app folder under the Windows-standard %APPDATA%
    # (falls back to ~/AppData/Roaming when APPDATA is unset, as off-Windows here)
    assert win.config_dir().name == "ssh-manager"
    assert win.config_dir().parent.name == "Roaming"
    # APPDATA wins when set
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    assert Windows().config_dir() == tmp_path / "AppData" / "Roaming" / "ssh-manager"


# real-Windows integration (runs on CI's windows-latest)
@win32_only
def test_real_icacls_restricts_to_owner(tmp_path: Path) -> None:
    f = tmp_path / "id_ed25519"
    f.write_text("private")
    Windows().set_perms(f, 0o600)
    out = subprocess.run(["icacls", str(f)], capture_output=True, text=True).stdout
    assert "(F)" in out                                       # a full-control ACE exists
    # The broad principals appear in icacls output as "Everyone:(...)" / "...\Users:(...)";
    # match the colon so the file path itself (C:\Users\...) is not a false positive.
    assert "Everyone:" not in out and "Users:" not in out     # inheritance stripped


@win32_only
def test_real_schtasks_creates_and_queries_task() -> None:
    label = "ssh_manager.citest"
    try:
        Windows().install_scheduler("cmd /c echo sshmgr", label=label)
        q = subprocess.run(["schtasks", "/Query", "/TN", label],
                           capture_output=True, text=True)
        assert q.returncode == 0 and label in q.stdout
    finally:
        subprocess.run(["schtasks", "/Delete", "/TN", label, "/F"],
                       capture_output=True, text=True)


def test_windows_flow_logic_on_any_os_with_stubbed_perms(tmp_path, monkeypatch) -> None:
    """The full init -> reconcile -> doctor flow driven by the *Windows* platform
    object, runnable on ANY OS: only ``set_perms`` is stubbed (to chmod) so the real
    ``icacls`` call - covered separately by the win32_only test below - isn't needed.

    This proves the Windows platform's flow LOGIC (config_dir/ssh_dir, key minting,
    config render, doctor) is sound on every CI runner, so the win32-only e2e only has
    to validate the icacls primitive. Together they back ``first_class = True``."""
    import os as _os

    from ssh_manager.services.facade import SshManagerService
    monkeypatch.setattr(Windows, "set_perms",
                        lambda self, p, m: _os.chmod(p, m) if p.exists() else None)
    home, ssh = tmp_path / "home", tmp_path / ".ssh"
    svc = SshManagerService(env={"SSH_MANAGER_HOME": str(home)}, ssh_dir=ssh, platform=Windows())
    svc.init()
    svc.profile_add("work")
    svc.host_add("work", "box", hostname="10.0.0.9", user="admin", provider="generic-ssh")
    svc.reconcile(auto_pin=False)
    assert (ssh / "profiles" / "work" / "work_box-ed25519").exists()    # minted
    assert (ssh / "config").exists()                                    # rendered
    rep = svc.doctor()
    assert rep.config_in_sync and not rep.perm_issues                   # flow sound


@win32_only
def test_real_reconcile_perms_and_config_end_to_end(tmp_path: Path) -> None:
    """The full flow on real Windows (the basis for first_class): init the home,
    add a host, reconcile (mint a key via ssh-keygen, render config, set ACLs via
    icacls), and assert doctor sees it in sync with no perm issues."""
    from ssh_manager.services.facade import SshManagerService
    home, ssh = tmp_path / "home", tmp_path / ".ssh"
    svc = SshManagerService(env={"SSH_MANAGER_HOME": str(home)}, ssh_dir=ssh, platform=Windows())
    svc.init()
    svc.profile_add("work")
    svc.host_add("work", "box", hostname="10.0.0.9", user="admin", provider="generic-ssh")
    svc.reconcile(auto_pin=False)                                  # offline (no ssh-keyscan)
    key = ssh / "profiles" / "work" / "work_box-ed25519"
    assert key.exists() and key.with_suffix(".pub").exists()       # minted
    assert (ssh / "config").exists()                               # rendered
    out = subprocess.run(["icacls", str(key)], capture_output=True, text=True).stdout
    assert "(F)" in out and "Everyone" not in out                  # owner-only ACL set
    rep = svc.doctor()
    assert rep.config_in_sync and not rep.perm_issues
