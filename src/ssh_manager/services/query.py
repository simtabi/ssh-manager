"""Read-only views over the manifest + inventory (`list` / `view`).

Returns *structured data* only; rendering lives in ``ssh_manager.render`` (rich), so
the surfaces (CLI/TUI/desktop) format it however they like. Provider *category*
powers ``--type``; free-form ``tags`` power ``--tag``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.inventory import Inventory, KeyRecord
from ..core.manifest import Host, Manifest
from ..providers.registry import resolve as resolve_provider
from ..util.errors import SshManagerError

NO_KEY = "no-key"
NEEDS_REDEPLOY = "needs-redeploy"
DEPLOYED = "deployed"


@dataclass(frozen=True)
class HostRow:
    alias: str
    hostname: str
    provider_label: str       # e.g. "github/vcs" or "server"
    key_name: str
    status: str               # no-key | needs-redeploy | deployed
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProfileGroup:
    name: str
    empty: bool
    rows: list[HostRow] = field(default_factory=list)


@dataclass(frozen=True)
class DeploymentRow:
    target: str
    method: str
    verified: bool


@dataclass(frozen=True)
class HostDetail:
    profile: str
    alias: str
    hostname: str
    user: str
    port: int
    identity_file: str
    known_hosts: str
    provider_label: str
    key_name: str
    status: str
    fingerprint: str | None = None
    expires_on: str | None = None
    tags: list[str] = field(default_factory=list)
    raw_options: dict[str, str] = field(default_factory=dict)
    deployments: list[DeploymentRow] = field(default_factory=list)
    requires_vpn: bool = False
    vpn_name: str | None = None
    vpn_url: str | None = None


@dataclass(frozen=True)
class ProfileSummary:
    name: str
    key_scope: str
    rows: list[HostRow] = field(default_factory=list)


class Query:
    def __init__(self, manifest: Manifest, inventory: Inventory,
                 ssh_dir: Path, providers_file: Path) -> None:
        self._m = manifest
        self._inv = inventory
        self._ssh = ssh_dir
        self._categories = _load_categories(providers_file)
        self._by_path: dict[str, KeyRecord] = {r.path: r for r in inventory.keys.values()}

    def category_of(self, provider: str | None) -> str:
        if provider and provider in self._categories:
            return self._categories[provider]
        return resolve_provider(provider).category

    def groups(self, *, profile: str | None = None, provider: str | None = None,
               type_: str | None = None, tag: str | None = None) -> list[ProfileGroup]:
        filtered = any((profile, provider, type_, tag))
        out: list[ProfileGroup] = []
        for pname, prof in self._m.profiles.items():
            if profile and pname != profile:
                continue
            rows: list[HostRow] = []
            for host in prof.hosts:
                if provider and host.provider != provider:
                    continue
                if type_ and self.category_of(host.provider) != type_:
                    continue
                if tag and tag not in host.tags:
                    continue
                rows.append(self._row(pname, host))
            if rows or (not filtered and not prof.hosts):
                out.append(ProfileGroup(name=pname, empty=not prof.hosts, rows=rows))
        return out

    def detail(self, selector: str) -> ProfileSummary | HostDetail:
        if selector in self._m.profiles:
            prof = self._m.profiles[selector]
            return ProfileSummary(
                name=selector, key_scope=prof.key_scope,
                rows=[self._row(selector, h) for h in prof.hosts],
            )
        for pname, prof in self._m.profiles.items():
            for host in prof.hosts:
                if host.alias == selector:
                    return self._host_detail(pname, host)
        raise SshManagerError(f"no profile or host alias matches {selector!r}")

    # helpers
    def _provider_label(self, host: Host) -> str:
        cat = self.category_of(host.provider)
        return f"{host.provider}/{cat}" if host.provider else cat

    def _row(self, pname: str, host: Host) -> HostRow:
        kname = self._m.resolved_key_name(pname, host)
        rec = self._by_path.get(self._m.identity_file(pname, kname))
        return HostRow(
            alias=host.alias, hostname=host.hostname,
            provider_label=self._provider_label(host), key_name=kname,
            status=self._status(rec), tags=list(host.tags),
        )

    def _host_detail(self, pname: str, host: Host) -> HostDetail:
        kname = self._m.resolved_key_name(pname, host)
        ident = self._m.identity_file(pname, kname)
        rec = self._by_path.get(ident)
        fp = next((f for f, r in self._inv.keys.items() if r.path == ident), None)
        deps = [DeploymentRow(d.target, d.method, d.verified)
                for d in (rec.deployments if rec else [])]
        return HostDetail(
            profile=pname, alias=host.alias, hostname=host.hostname, user=host.user,
            port=host.port, identity_file=ident,
            known_hosts=self._m.known_hosts_file(pname),
            provider_label=self._provider_label(host),
            key_name=kname, status=self._status(rec),
            fingerprint=fp, expires_on=rec.expires_on if rec else None,
            tags=list(host.tags), raw_options=dict(host.raw_options), deployments=deps,
            requires_vpn=host.requires_vpn, vpn_name=host.vpn_name, vpn_url=host.vpn_url,
        )

    def _status(self, rec: KeyRecord | None) -> str:
        if rec is None:
            return NO_KEY
        return NEEDS_REDEPLOY if rec.needs_redeploy else DEPLOYED


def _load_categories(providers_file: Path) -> dict[str, str]:
    """Provider name -> category, from the layered catalog (built-ins + the user's
    providers.json if present, else the shipped default). Routing through the
    registry means `list --type`/category lookups honor the same fallback as
    deploy/resolve - not just a user file that may not exist."""
    from ..providers.registry import all_specs
    return {name: spec.category for name, spec in all_specs(providers_file).items()}
