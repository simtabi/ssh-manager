"""Presentation layer (rich) - turns service data into terminal renderables.

Kept separate from the Facade (which returns data) so every surface (CLI, TUI,
future desktop) formats consistently and we never hand-roll tables/trees. rich
auto-detects the terminal: colour + box-drawing on a TTY, plain text in a pipe.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .core.expiry import DUE_SOON, OK, OVERDUE, ExpiryStatus
from .services.query import (
    DEPLOYED,
    NEEDS_REDEPLOY,
    NO_KEY,
    HostDetail,
    HostRow,
    ProfileGroup,
    ProfileSummary,
)

# status token -> (rich style, glyph)
_STATUS = {
    DEPLOYED: ("green", "✓"),
    NEEDS_REDEPLOY: ("yellow", "⚠"),
    NO_KEY: ("dim", "·"),
    OK: ("green", "✓"),
    DUE_SOON: ("yellow", "⚠"),
    OVERDUE: ("red", "✗"),
    "verified": ("green", "✓"),
    "unverified": ("yellow", "⚠"),
}


def console(*, stderr: bool = False) -> Console:
    return Console(stderr=stderr, highlight=False)


def status_text(status: str) -> Text:
    style, glyph = _STATUS.get(status, ("white", "•"))
    return Text(f"{glyph} {status}", style=style)


# list
def list_tree(groups: Iterable[ProfileGroup]) -> RenderableType:
    groups = list(groups)
    if not groups:
        return Text("manifest has no profiles", style="dim")
    root = Tree(Text("profiles", style="bold"))
    for g in groups:
        label = Text(g.name, style="bold cyan")
        if g.empty:
            label.append("  (empty)", style="dim")
        branch = root.add(label)
        for row in g.rows:
            branch.add(_host_row_text(row))
    return root


def _host_row_text(row: HostRow) -> Text:
    t = Text()
    t.append(f"{row.alias:<18} ", style="bold")
    t.append(f"{row.hostname:<20}", style="cyan")
    t.append(f" {row.provider_label:<14} ")
    t.append(f"{row.key_name} ")
    t.append_text(status_text(row.status))
    if row.tags:
        t.append(f"  [{','.join(row.tags)}]", style="magenta")
    return t


def no_match() -> RenderableType:
    return Text("no hosts match the given filter", style="yellow")


# view
def profile_summary(summary: ProfileSummary) -> RenderableType:
    tree = Tree(Text(f"profile {summary.name} ", style="bold cyan").append(
        f"({summary.key_scope}, {len(summary.rows)} host(s))", style="dim"))
    for row in summary.rows:
        tree.add(_host_row_text(row))
    return tree


def host_detail(d: HostDetail) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right")
    grid.add_column()
    grid.add_row("HostName", d.hostname)
    grid.add_row("User", d.user)
    grid.add_row("Port", str(d.port))
    grid.add_row("IdentityFile", d.identity_file)
    grid.add_row("UserKnownHostsFile", d.known_hosts)
    grid.add_row("provider", d.provider_label)
    if d.requires_vpn:
        vpn = d.vpn_name or "VPN"
        at = f" at {d.vpn_url}" if d.vpn_url else ""
        grid.add_row("network", Text(f"requires VPN ({vpn}){at} - connect it before deploy/rotate",
                                     style="yellow"))
    if d.tags:
        grid.add_row("tags", ", ".join(d.tags))
    for k, v in d.raw_options.items():
        grid.add_row(k, v)
    grid.add_row("key", Text(d.key_name).append("  ").append_text(status_text(d.status)))
    if d.fingerprint:
        grid.add_row("fingerprint", d.fingerprint)
    if d.expires_on:
        grid.add_row("expires_on", d.expires_on)
    body: list[RenderableType] = [grid]
    if d.deployments:
        dep = Table(box=None, show_header=False, padding=(0, 2))
        for x in d.deployments:
            flag = "verified" if x.verified else "unverified"
            dep.add_row("→", x.target, x.method, status_text(flag))
        body.append(Text("deployments:", style="dim"))
        body.append(dep)
    else:
        body.append(Text("deployments: none (needs-redeploy)", style="yellow"))
        body.append(Text(f"→ deploy with: sshmgr deploy {d.key_name}", style="green"))
    return Panel(Group(*body), title=f"host {d.alias}  (profile {d.profile})",
                 border_style="cyan", title_align="left")


# providers
def providers_table(infos: list[Any]) -> RenderableType:
    if not infos:
        return Text("no providers configured", style="dim")
    table = Table(title="Providers", title_style="bold", header_style="bold")
    table.add_column("NAME")
    table.add_column("KIND")
    table.add_column("CATEGORY")
    table.add_column("TOKEN_ENV")
    table.add_column("CREDENTIAL")
    for p in infos:
        cred = (Text("✓ set", style="green") if p.token_present
                else Text("- none" if p.token_env else "n/a", style="dim"))
        table.add_row(p.name, p.kind, p.category, p.token_env or "-", cred)
    return table


# network / VPN reachability
def network_table(rows: list[Any]) -> RenderableType:
    if not rows:
        return Text("no hosts in the manifest", style="dim")
    any_vpn = any(r.status.vpn for r in rows)
    vpn_line = Text(f"VPN/tunnel interface: {'detected' if any_vpn else 'none detected'}",
                    style="dim")
    table = Table(title="Network reachability", title_style="bold", header_style="bold")
    table.add_column("PROFILE")
    table.add_column("HOST")
    table.add_column("ADDRESS")
    table.add_column("STATUS")
    table.add_column("NOTE")
    for r in rows:
        st = r.status
        status = (Text("● online", style="green") if st.reachable
                  else Text("○ offline", style="red"))
        vpn = f" ({st.vpn_name})" if st.vpn_name else ""
        url = f" {st.vpn_url}" if st.vpn_url else ""
        note: RenderableType = ""
        if not st.reachable and st.requires_vpn:
            note = Text(f"needs VPN{vpn}{url}", style="yellow")
        elif st.requires_vpn:
            note = Text(f"VPN{vpn}", style="dim")
        table.add_row(r.profile, r.alias, f"{st.host}:{st.port}", status, note)
    return Group(table, vpn_line)


# key validation
def validate_table(checks: list[Any]) -> RenderableType:
    if not checks:
        return Text("no managed keys to validate (run reconcile)", style="dim")
    table = Table(title="Key validation", title_style="bold", header_style="bold")
    table.add_column("KEY")
    table.add_column("PROFILE")
    table.add_column("FINGERPRINT")
    table.add_column("STATUS")
    table.add_column("ISSUES")
    for c in checks:
        status = (Text("✓ ok", style="green") if c.ok
                  else Text("✗ fail", style="red bold"))
        detail = "; ".join([*c.issues, *getattr(c, "notes", [])]) or "-"
        table.add_row(c.key_name, c.profile, c.fingerprint or "-", status, detail)
    return table


# expiry
def expiry_table(states: list[ExpiryStatus]) -> RenderableType:
    if not states:
        return Text("no keys tracked yet (run reconcile)", style="dim")
    table = Table(title="Key expiry", title_style="bold", header_style="bold")
    table.add_column("KEY")
    table.add_column("PROFILE")
    table.add_column("EXPIRES_ON")
    table.add_column("DAYS", justify="right")
    table.add_column("STATE")
    for s in states:
        days = "?" if s.days_remaining is None else str(s.days_remaining)
        table.add_row(s.key_name, s.profile, s.expires_on or "?", days,
                      status_text(s.state))
    return table
