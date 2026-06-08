"""Linux platform: systemd --user timer + cron fallback (the Linux pass)."""
from __future__ import annotations

from pathlib import Path

from ssh_manager.platforms.linux import Linux


class _Resp:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_linux_is_first_class_and_drops_use_keychain() -> None:
    lin = Linux()
    assert lin.first_class is True
    assert lin.emits_use_keychain is False        # UseKeychain is macOS-only


def test_install_systemd_user_timer(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    calls: list[list[str]] = []
    def rec(c, **k):
        calls.append(c)
        return _Resp()

    monkeypatch.setattr("ssh_manager.platforms.linux.proc.has", lambda b: b == "systemctl")
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run", rec)
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run_checked", rec)

    Linux().install_scheduler("/usr/bin/sshmgr audit --notify")

    unit_dir = tmp_path / ".config/systemd/user"
    service = (unit_dir / "ssh_manager.expiry.service").read_text()
    timer = (unit_dir / "ssh_manager.expiry.timer").read_text()
    assert "ExecStart=/usr/bin/sshmgr audit --notify" in service
    assert "OnCalendar=" in timer and "WantedBy=timers.target" in timer
    assert ["systemctl", "--user", "daemon-reload"] in calls
    assert any("enable" in c and "ssh_manager.expiry.timer" in c for c in calls)


def test_install_cron_fallback(monkeypatch) -> None:
    written: dict[str, str] = {}
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.has",
                        lambda b: b == "crontab")            # no systemctl
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run",
                        lambda c, **k: _Resp(returncode=1))   # no existing crontab

    def run_checked(cmd, input_=None, **k):
        written["input"] = input_ or ""
        return _Resp()

    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run_checked", run_checked)
    Linux().install_scheduler("sshmgr audit --notify")
    assert "0 9 * * * sshmgr audit --notify # ssh_manager.expiry" in written["input"]


def test_systemd_install_strips_stale_cron(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    writes: list[str] = []

    def run(c, input_=None, **k):
        if c[:2] == ["crontab", "-l"]:
            return _Resp(stdout="0 9 * * * old # ssh_manager.expiry\nMAILTO=me\n")
        if c == ["crontab", "-"]:
            writes.append(input_ or "")
        return _Resp()

    monkeypatch.setattr("ssh_manager.platforms.linux.proc.has",
                        lambda b: b in ("systemctl", "crontab"))
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run", run)
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run_checked", run)
    Linux().install_scheduler("sshmgr audit --notify")            # takes systemd path
    # the stale cron entry was rewritten out (no double-fire), keeping MAILTO
    assert writes and all("ssh_manager.expiry" not in w for w in writes)
    assert "MAILTO=me" in writes[-1]


def test_cron_install_removes_stale_units(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    unit_dir = tmp_path / ".config/systemd/user"
    unit_dir.mkdir(parents=True)
    timer = unit_dir / "ssh_manager.expiry.timer"
    timer.write_text("stale")
    (unit_dir / "ssh_manager.expiry.service").write_text("stale")

    def run(c, input_=None, **k):
        return _Resp(returncode=1) if c[:2] == ["crontab", "-l"] else _Resp()

    monkeypatch.setattr("ssh_manager.platforms.linux.proc.has", lambda b: b == "crontab")
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run", run)
    monkeypatch.setattr("ssh_manager.platforms.linux.proc.run_checked", run)
    Linux().install_scheduler("cmd")                              # takes cron path
    assert not timer.exists()                                     # stale timer removed
