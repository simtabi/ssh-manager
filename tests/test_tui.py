"""TUI navigation tests via a scripted Prompter (no TTY needed)."""
from __future__ import annotations

import io
from collections.abc import Sequence

from rich.console import Console

from ssh_manager.providers.base import DeployOutcome
from ssh_manager.providers.ssh_generic import GenericSSH
from ssh_manager.services.facade import SshManagerService
from ssh_manager.tui import MENU, Tui


class FakePrompter:
    def __init__(self, selects: list[str | None] | None = None,
                 confirms: list[bool] | None = None) -> None:
        self._selects = list(selects or [])
        self._confirms = list(confirms or [])
        self.select_calls: list[tuple[str, list[str]]] = []
        self.confirm_calls: list[str] = []

    def select(self, message: str, choices: Sequence[str]) -> str | None:
        self.select_calls.append((message, list(choices)))
        return self._selects.pop(0) if self._selects else None

    def confirm(self, message: str) -> bool:
        self.confirm_calls.append(message)
        return self._confirms.pop(0) if self._confirms else False


def _run(svc: SshManagerService, selects, confirms=None) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False)
    Tui(service=svc, prompter=FakePrompter(selects, confirms), console=console).run()
    return buf.getvalue()


def test_menu_structure_marks_destructive() -> None:
    labels = [m.label for m in MENU]
    assert "Browse profiles & hosts" in labels
    assert MENU[-1].handler == "quit"
    destructive = {m.handler for m in MENU if m.destructive}
    assert destructive == {"rotate", "snapshots"}


def test_browse_drills_into_host(svc: SshManagerService) -> None:
    svc.reconcile()
    out = _run(svc, selects=["Browse profiles & hosts", "work", "unc", "Quit"])
    assert "profile work" in out                       # profile summary tree
    assert "host unc" in out                            # host detail panel title
    assert "work_unc-ed25519" in out                    # the key + path inside the panel


def test_show_config_and_expiry(svc: SshManagerService) -> None:
    svc.reconcile()
    out = _run(svc, selects=["Show rendered config", "Expiry status", "Quit"])
    assert "Include profiles/*/config" in out
    assert "STATE" in out                               # expiry table header


def test_reconcile_via_tui_applies_on_confirm(svc: SshManagerService) -> None:
    out = _run(svc, selects=["Reconcile (apply manifest)", "Quit"], confirms=[True])
    assert (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519").exists()
    assert "reconcile" in out


def test_rotate_cancelled_does_nothing(svc: SshManagerService) -> None:
    svc.reconcile()
    out = _run(svc, selects=["Rotate a key", "work_unc-ed25519", "Quit"], confirms=[False])
    assert "cancelled" in out
    assert not (svc.paths.ssh_dir / "profiles/work/old").exists()   # no rotation happened


def test_rotate_confirmed_runs(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr(GenericSSH, "verify", lambda self, t: True)
    monkeypatch.setattr(GenericSSH, "remove", lambda self, t: True)
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    svc.reconcile()
    out = _run(svc, selects=["Rotate a key", "work_unc-ed25519", "Quit"], confirms=[True])
    assert (svc.paths.ssh_dir / "profiles/work/old/work_unc-ed25519").exists()
    assert "rotated" in out


def test_back_choice_returns_to_menu(svc: SshManagerService) -> None:
    svc.reconcile()
    # select Browse, then "← back" at the profile picker, then Quit
    out = _run(svc, selects=["Browse profiles & hosts", "← back", "Quit"])
    assert "profile" not in out      # never drilled in
