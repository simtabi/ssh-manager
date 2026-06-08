"""Read-path tests: list/view return structured data; render produces rich output."""
from __future__ import annotations

import io

from rich.console import Console

from ssh_manager import render
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.query import HostDetail, ProfileSummary


def _aliases(groups) -> set[str]:
    return {row.alias for g in groups for row in g.rows}


def test_list_groups_and_status(svc: SshManagerService) -> None:
    groups = svc.list_groups()
    names = {g.name for g in groups}
    assert "work" in names and "school" in names
    assert next(g for g in groups if g.name == "school").empty
    # before reconcile: no key on disk
    assert next(g for g in groups if g.name == "work").rows[0].status == "no-key"
    svc.reconcile()
    assert next(g for g in svc.list_groups() if g.name == "work").rows[0].status \
        == "needs-redeploy"


def test_list_type_filter_uses_provider_category(svc: SshManagerService) -> None:
    aliases = _aliases(svc.list_groups(type_="vcs"))
    assert {"github.com", "github-simtabi"} <= aliases
    assert "unc" not in aliases             # work/unc is generic ssh, not vcs


def test_list_tag_and_provider_filters(svc: SshManagerService) -> None:
    assert "oribi-web" in _aliases(svc.list_groups(tag="app"))
    assert svc.list_groups(tag="db") == []      # nothing tagged db in the fixture
    assert "oribi-web" in _aliases(svc.list_groups(provider="ploi"))
    assert svc.list_groups(provider="nonesuch") == []


def test_view_profile_and_host(svc: SshManagerService) -> None:
    prof = svc.view_detail("simtabi")
    assert isinstance(prof, ProfileSummary) and prof.rows[0].alias == "github-simtabi"
    host = svc.view_detail("github-simtabi")
    assert isinstance(host, HostDetail)
    assert host.identity_file == "~/.ssh/profiles/simtabi/simtabi_github-ed25519"
    assert "vcs" in host.provider_label


def test_view_shows_deployment_status_after_reconcile(svc: SshManagerService) -> None:
    svc.reconcile()
    host = svc.view_detail("unc")
    assert isinstance(host, HostDetail)
    assert host.fingerprint and host.fingerprint.startswith("SHA256:")
    assert host.deployments == []           # minted, not yet deployed


def test_render_produces_rich_output(svc: SshManagerService) -> None:
    svc.reconcile()
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False)
    console.print(render.list_tree(svc.list_groups()))
    console.print(render.expiry_table(svc.expiry_states()))
    console.print(render.host_detail(svc.view_detail("unc")))
    out = buf.getvalue()
    assert "work_unc-ed25519" in out and "github-simtabi" in out   # tree
    assert "STATE" in out and "EXPIRES_ON" in out                  # expiry table headers
    assert "sc.its.unc.edu" in out                                 # host detail panel
