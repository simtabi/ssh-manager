"""Interactive TUI (rich + questionary) over the same Facade.

Browse profiles → hosts, preview the rendered config + deployments, and run the
same operations as the CLI behind menus and confirmations on destructive actions.
No business logic lives here - every action calls the Facade.

Interaction goes through a small ``Prompter`` seam: production wraps
``questionary``; tests inject a scripted fake, so the navigation loop is testable
without a TTY.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from rich.console import Console

from . import render
from .services.facade import SshManagerService
from .services.query import ProfileSummary
from .util.errors import SshManagerError

BACK = "← back"
CANCEL = "(cancel)"


class Prompter(Protocol):
    def select(self, message: str, choices: Sequence[str]) -> str | None: ...
    def confirm(self, message: str) -> bool: ...


class QuestionaryPrompter:
    """Production prompter - arrow-key menus + yes/no over questionary."""

    def select(self, message: str, choices: Sequence[str]) -> str | None:
        import questionary
        result = questionary.select(message, choices=list(choices)).ask()
        return result if isinstance(result, str) else None

    def confirm(self, message: str) -> bool:
        import questionary
        return bool(questionary.confirm(message).ask())


@dataclass(frozen=True)
class MenuItem:
    label: str
    handler: str
    destructive: bool = False


MENU: list[MenuItem] = [
    MenuItem("Browse profiles & hosts", "browse"),
    MenuItem("Show rendered config", "show_config"),
    MenuItem("Expiry status", "expiry"),
    MenuItem("Audit (deployments + expiry)", "audit"),
    MenuItem("Reconcile (apply manifest)", "reconcile"),
    MenuItem("Pin host keys (known_hosts)", "knownhosts"),
    MenuItem("Deploy a key", "deploy"),
    MenuItem("Rotate a key", "rotate", destructive=True),
    MenuItem("Snapshots (list / restore)", "snapshots", destructive=True),
    MenuItem("Quit", "quit"),
]


class Tui:
    def __init__(self, service: SshManagerService | None = None,
                 prompter: Prompter | None = None,
                 console: Console | None = None) -> None:
        self._svc = service or SshManagerService()
        self._prompter = prompter or QuestionaryPrompter()
        self._console = console or Console()

    # main loop
    def run(self) -> None:
        self._banner()
        while True:
            choice = self._prompter.select("ssh-manager", [m.label for m in MENU])
            item = next((m for m in MENU if m.label == choice), None)
            if item is None or item.handler == "quit":
                return
            getattr(self, f"_{item.handler}")()

    # handlers (thin over the Facade)
    def _browse(self) -> None:
        profiles = self._profile_names()
        if not profiles:
            self._print("no profiles - run init / edit the manifest")
            return
        p = self._prompter.select("Profile", [*profiles, BACK])
        if not p or p == BACK:
            return
        self._view(p)
        hosts = self._host_aliases(p)
        if hosts:
            h = self._prompter.select("Host", [*hosts, BACK])
            if h and h != BACK:
                self._view(h)

    def _view(self, selector: str) -> None:
        try:
            detail = self._svc.view_detail(selector)
        except SshManagerError as exc:
            self._print(f"error: {exc}")
            return
        if isinstance(detail, ProfileSummary):
            self._console.print(render.profile_summary(detail))
        else:
            self._console.print(render.host_detail(detail))

    def _show_config(self) -> None:
        self._print(self._safe(lambda: self._svc.config_show(None)))

    def _expiry(self) -> None:
        try:
            self._console.print(render.expiry_table(self._svc.expiry_states()))
        except SshManagerError as exc:
            self._print(f"error: {exc}")

    def _audit(self) -> None:
        self._print(self._safe(self._svc.audit))

    def _reconcile(self) -> None:
        self._print(self._safe(lambda: self._svc.reconcile(dry_run=True).format()))
        if self._prompter.confirm("Apply these changes to ~/.ssh?"):
            self._print(self._safe(lambda: self._svc.reconcile().format()))

    def _knownhosts(self) -> None:
        # Initialize every profile's trust store (create file + pin reachable hosts).
        # Non-destructive (trust-on-first-use, add-only); fingerprints are reported.
        self._print(self._safe(
            lambda: self._svc.init_known_hosts(all_profiles=True).format()))

    def _deploy(self) -> None:
        keys = self._key_names()
        if not keys:
            self._print("no keys yet - reconcile first")
            return
        k = self._prompter.select("Key to deploy", [*keys, BACK])
        if not k or k == BACK:
            return
        self._print(self._safe(lambda: self._svc.deploy(k).format()))

    def _rotate(self) -> None:
        keys = self._key_names()
        if not keys:
            self._print("no keys yet - reconcile first")
            return
        k = self._prompter.select("Key to rotate", [*keys, BACK])
        if not k or k == BACK:
            return
        if not self._prompter.confirm(f"Rotate {k}? (destructive; ~/.ssh snapshotted first)"):
            self._print("cancelled")
            return
        self._print(self._safe(lambda: self._svc.rotate(k).format()))

    def _snapshots(self) -> None:
        snaps = self._svc.list_snapshots()
        if not snaps:
            self._print("no snapshots yet")
            return
        choice = self._prompter.select(
            "Restore which snapshot?", [CANCEL, *[s.name for s in snaps]]
        )
        if not choice or choice == CANCEL:
            return
        if self._prompter.confirm(f"Restore {choice}? (current tree snapshotted first)"):
            self._print(self._safe(
                lambda: f"restored from {self._svc.restore_snapshot(choice).name}"
            ))

    # helpers
    def _banner(self) -> None:
        try:
            text = self._svc.expiry_banner()
        except SshManagerError:
            text = ""
        if text:
            self._console.print(text, style="yellow", markup=False, highlight=False)

    def _print(self, text: str) -> None:
        # markup off so bracketed status like "[needs-redeploy]" isn't parsed
        self._console.print(text, markup=False, highlight=False)

    def _safe(self, fn: Callable[[], str]) -> str:
        try:
            return fn()
        except SshManagerError as exc:
            return f"error: {exc}"

    def _profile_names(self) -> list[str]:
        try:
            return list(self._svc.manifest().profiles)
        except SshManagerError:
            return []

    def _host_aliases(self, profile: str) -> list[str]:
        return [h.alias for h in self._svc.manifest().profiles[profile].hosts]

    def _key_names(self) -> list[str]:
        try:
            return sorted({rk.key_name for rk in self._svc.manifest().iter_resolved()})
        except SshManagerError:
            return []


def run() -> None:  # pragma: no cover - interactive entrypoint
    Tui().run()
