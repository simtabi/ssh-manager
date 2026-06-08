"""Deploy a key's public half to its target(s) and record it.

Resolution: a key_name maps to the host(s) that reference it (one for
``per_service``, many for ``shared``). Each target's provider does the install
(named adapter → generic ssh → manual), and the result is recorded in the
inventory keyed by fingerprint - the join that later makes rotation a checklist.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.inventory import Deployment, Inventory, KeyRecord, today
from ..core.manifest import Host, Manifest
from ..platforms.base import Platform
from ..providers.base import Target
from ..providers.registry import resolve as resolve_provider
from ..util import log, net
from ..util.errors import SshManagerError
from ..util.paths import Paths
from .keystore import KeyStore


@dataclass
class DeployRecord:
    target: str
    provider: str
    method: str
    verified: bool
    detail: str = ""
    error: bool = False   # an automated deploy was attempted and failed (or unreachable)


@dataclass
class DeployReport:
    key_name: str
    fingerprint: str
    records: list[DeployRecord] = field(default_factory=list)

    def format(self) -> str:
        lines = [f"deploy {self.key_name}  ({self.fingerprint})"]
        for r in self.records:
            flag = "verified" if r.verified else "MANUAL/needs-redeploy"
            lines.append(f"  -> {r.target} via {r.provider}/{r.method}: {flag}")
            if r.detail:
                lines.append(f"     {r.detail}")
        return "\n".join(lines)


class Deployer:
    def __init__(self, platform: Platform, paths: Paths,
                 manifest: Manifest, inventory: Inventory) -> None:
        self._platform = platform
        self._paths = paths
        self._manifest = manifest
        self._inventory = inventory
        self._keystore = KeyStore(platform)

    def deploy(self, key_name: str, target_alias: str | None = None) -> DeployReport:
        hosts = self._targets(key_name, target_alias)
        profile = self._profile_for(key_name)
        pub = self._paths.ssh_dir / "profiles" / profile / f"{key_name}.pub"
        if not pub.exists():
            raise SshManagerError(f"public key not found: {pub} - run `sshmgr reconcile` first")
        fp = self._keystore.fingerprint(pub)
        rec = self._ensure_record(fp, profile, key_name)

        report = DeployReport(key_name=key_name, fingerprint=fp)
        for host in hosts:
            provider = resolve_provider(host.provider, self._paths.providers)
            # Reachability precheck for SSH-to-host providers: fail fast (with a
            # VPN-aware message) instead of hanging on an unreachable / VPN-gated host.
            if provider.category == "server":
                st = net.check(host.hostname, host.port, ssh=True,
                               requires_vpn=host.requires_vpn, vpn_name=host.vpn_name,
                               vpn_url=host.vpn_url)
                if not st.reachable:
                    self._record_deployment(rec, host.alias, "unreachable", False)
                    report.records.append(DeployRecord(
                        target=host.alias, provider=provider.name, method="unreachable",
                        verified=False, detail=st.message, error=True))
                    log.audit(self._paths.audit_log, "deploy.unreachable",
                              key=key_name, target=host.alias, hostname=host.hostname)
                    continue
            tgt = Target(
                alias=host.alias, hostname=host.hostname, user=host.user, port=host.port,
                pubkey_path=pub, pubkey_text=pub.read_text(encoding="utf-8"),
                token_env=host.token_env,
                known_hosts=self._paths.ssh_dir / "profiles" / profile / "known_hosts",
            )
            outcome = provider.deploy(tgt)
            self._record_deployment(rec, host.alias, outcome.method, outcome.verified)
            report.records.append(DeployRecord(
                target=host.alias, provider=provider.name, method=outcome.method,
                verified=outcome.verified, detail=outcome.detail, error=outcome.error,
            ))
            log.audit(self._paths.audit_log, "deploy", key=key_name, fingerprint=fp,
                      target=host.alias, provider=provider.name,
                      method=outcome.method, verified=outcome.verified)
        return report

    # resolution
    def _targets(self, key_name: str, target_alias: str | None) -> list[Host]:
        using = [
            rk.host for rk in self._manifest.iter_resolved() if rk.key_name == key_name
        ]
        if not using:
            raise SshManagerError(f"no host in the manifest uses key {key_name!r}")
        if target_alias is None:
            return using
        chosen = [h for h in using if h.alias == target_alias]
        if not chosen:
            raise SshManagerError(
                f"host {target_alias!r} does not use key {key_name!r} "
                f"(it's used by: {', '.join(h.alias for h in using)})"
            )
        return chosen

    def _profile_for(self, key_name: str) -> str:
        for rk in self._manifest.iter_resolved():
            if rk.key_name == key_name:
                return rk.profile
        raise SshManagerError(f"no host in the manifest uses key {key_name!r}")

    # inventory
    def _ensure_record(self, fp: str, profile: str, key_name: str) -> KeyRecord:
        rec = self._inventory.keys.get(fp)
        if rec is None:
            rec = KeyRecord(
                profile=profile,
                path=str(self._manifest.identity_file(profile, key_name)),
            )
            self._inventory.record(fp, rec)
        return rec

    def _record_deployment(self, rec: KeyRecord, target: str,
                           method: str, verified: bool) -> None:
        # Idempotent: one entry per target - replace any existing record for it.
        rec.deployments = [d for d in rec.deployments if d.target != target]
        rec.deployments.append(
            Deployment(target=target, method=method, date=today(), verified=verified)
        )
