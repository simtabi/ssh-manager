"""Zero-downtime, staged, single-old-archive rotation (invariant 7).

rotate: stage a replacement in ``.staging/`` → deploy the staged pubkey to every
target (the current key stays active) → verify login on each → commit ONLY after
all verify (purge any existing ``/old/`` predecessor, archive the current key
under the identical filename, promote staged, revoke old, reset inventory+audit).
On any failure before commit the staged key is discarded and the active key is
untouched. rollback is the symmetric reverse move of the single ``/old/`` key.
"""
from __future__ import annotations

import contextlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..core.inventory import (
    Deployment,
    Inventory,
    KeyRecord,
    compute_expiry,
    today,
)
from ..core.manifest import Host, Manifest
from ..platforms.base import Platform
from ..providers.base import Target
from ..providers.registry import resolve as resolve_provider
from ..util import fs, log, net, perms
from ..util.errors import SshManagerError
from ..util.paths import Paths
from .keystore import KeyStore


@dataclass
class TargetResult:
    alias: str
    provider: str
    deployed: bool = False
    verified: bool = False
    revoked: bool = False


@dataclass
class RotateReport:
    key_name: str
    old_fingerprint: str = ""
    new_fingerprint: str = ""
    committed: bool = False
    message: str = ""
    targets: list[TargetResult] = field(default_factory=list)

    def format(self) -> str:
        head = "rotated" if self.committed else "rotation ABORTED"
        lines = [f"{head}: {self.key_name}"]
        if self.old_fingerprint:
            lines.append(f"  old: {self.old_fingerprint}")
        if self.new_fingerprint:
            lines.append(f"  new: {self.new_fingerprint}")
        for t in self.targets:
            lines.append(
                f"  {t.alias} ({t.provider}): "
                f"deploy={'ok' if t.deployed else 'FAIL'} "
                f"verify={'ok' if t.verified else 'no'} "
                f"revoke={'ok' if t.revoked else '-'}"
            )
        if self.message:
            lines.append(f"  {self.message}")
        return "\n".join(lines)


class Rotator:
    def __init__(self, platform: Platform, paths: Paths,
                 manifest: Manifest, inventory: Inventory) -> None:
        self._platform = platform
        self._paths = paths
        self._manifest = manifest
        self._inventory = inventory
        self._keystore = KeyStore(platform)

    # path helpers
    def _profile_and_hosts(self, key_name: str) -> tuple[str, list[Host]]:
        matches = [rk for rk in self._manifest.iter_resolved() if rk.key_name == key_name]
        if not matches:
            raise SshManagerError(f"no host in the manifest uses key {key_name!r}")
        return matches[0].profile, [m.host for m in matches]

    def _dir(self, profile: str) -> Path:
        return self._paths.ssh_dir / "profiles" / profile

    def _unreachable_targets(self, hosts: list[Host]) -> list[net.NetStatus]:
        """Reachability of every SSH-to-host target (skips API/web-panel providers,
        whose 'host' is a service endpoint, not the box itself)."""
        out: list[net.NetStatus] = []
        for host in hosts:
            provider = resolve_provider(host.provider, self._paths.providers)
            if provider.category != "server":
                continue
            st = net.check(host.hostname, host.port, ssh=True,
                           requires_vpn=host.requires_vpn, vpn_name=host.vpn_name,
                           vpn_url=host.vpn_url)
            if not st.reachable:
                out.append(st)
        return out

    # rotate
    def rotate(self, key_name: str, *, allow_unverified: bool = False,
               passphrase: str = "") -> RotateReport:
        profile, hosts = self._profile_and_hosts(key_name)
        pdir = self._dir(profile)
        cur_priv, cur_pub = pdir / key_name, pdir / f"{key_name}.pub"
        if not cur_priv.exists():
            raise SshManagerError(f"key not present: {cur_priv} - run `sshmgr reconcile` first")

        report = RotateReport(key_name=key_name)
        report.old_fingerprint = self._keystore.fingerprint(cur_pub)
        old_pub_text = cur_pub.read_text(encoding="utf-8")

        # 0. Preflight reachability: every SSH target must answer before we stage or
        # deploy anything - so an unreachable / VPN-gated host fails fast with an
        # actionable message instead of hanging mid-rotation.
        unreachable = self._unreachable_targets(hosts)
        if unreachable:
            report.message = "cannot rotate - " + "; ".join(s.message for s in unreachable)
            log.audit(self._paths.audit_log, "rotate.unreachable", key=key_name)
            return report

        # 1. Stage a fresh keypair (discard any leftover from a crashed rotation).
        staging = pdir / ".staging"
        if staging.exists():
            shutil.rmtree(staging)
        fs.ensure_dir(staging, perms.DIR_MODE)
        staged_priv = staging / key_name
        comment = f"{profile}/{hosts[0].alias} {today()}"
        gen = self._keystore.generate(
            staged_priv, key_type=self._manifest.defaults.key_type, comment=comment,
            passphrase=passphrase,
        )
        report.new_fingerprint = gen.fingerprint
        staged_pub = staging / f"{key_name}.pub"

        # 2. Deploy the staged pubkey to every target (current key still active).
        # 3. Verify login with the staged key on each target.
        results: list[TargetResult] = []
        for host in hosts:
            provider = resolve_provider(host.provider, self._paths.providers)
            tr = TargetResult(alias=host.alias, provider=provider.name)
            tgt = Target(
                alias=host.alias, hostname=host.hostname, user=host.user, port=host.port,
                pubkey_path=staged_pub, pubkey_text=staged_pub.read_text(encoding="utf-8"),
                token_env=host.token_env, identity_path=staged_priv,
                known_hosts=pdir / "known_hosts",
            )
            outcome = provider.deploy(tgt)
            # "deploy ok" = an automated deploy that succeeded, OR a manual target
            # (the user will paste it). This is what --allow-unverified accepts.
            tr.deployed = outcome.method == "manual" or outcome.verified
            tr.verified = provider.verify(tgt)
            results.append(tr)
        report.targets = results

        # Commit if every target verified by login, OR --allow-unverified and every
        # target's deploy was acknowledged (covers manual/web-panel targets).
        ready = all(t.verified for t in results) or (
            allow_unverified and all(t.deployed for t in results)
        )
        if not ready:
            # Best-effort: pull the staged pubkey back off every target where the
            # deploy already landed, so an aborted rotation doesn't leave orphan
            # keys accumulating in authorized_keys / provider accounts.
            staged_text = staged_pub.read_text(encoding="utf-8")
            for host, tr in zip(hosts, results, strict=True):
                if not tr.deployed:
                    continue
                provider = resolve_provider(host.provider, self._paths.providers)
                with contextlib.suppress(Exception):
                    provider.remove(Target(
                        alias=host.alias, hostname=host.hostname, user=host.user,
                        port=host.port, pubkey_path=staged_pub, pubkey_text=staged_text,
                        token_env=host.token_env, known_hosts=pdir / "known_hosts",
                    ))
            shutil.rmtree(staging)        # 5. discard staged; active key untouched
            report.message = ("verification failed on one or more targets - staged key "
                              "discarded (and pulled back from any target it reached), "
                              "active key untouched. (Use --allow-unverified to accept "
                              "manual/web-panel targets.)")
            log.audit(self._paths.audit_log, "rotate.abort",
                      key=key_name, old=report.old_fingerprint)
            return report

        # 4. COMMIT (only after all verified).
        old_dir = pdir / "old"
        fs.ensure_dir(old_dir, perms.DIR_MODE)
        # purge any existing predecessor for this key (enforces ≤1-old)
        (old_dir / key_name).unlink(missing_ok=True)
        (old_dir / f"{key_name}.pub").unlink(missing_ok=True)
        # archive current under the identical filename
        cur_priv.replace(old_dir / key_name)
        cur_pub.replace(old_dir / f"{key_name}.pub")
        # promote staged to canonical
        staged_priv.replace(cur_priv)
        staged_pub.replace(cur_pub)
        self._platform.set_perms(cur_priv, perms.PRIVATE_KEY_MODE)
        self._platform.set_perms(cur_pub, perms.PUBLIC_KEY_MODE)
        self._platform.set_perms(old_dir / key_name, perms.PRIVATE_KEY_MODE)
        self._platform.set_perms(old_dir / f"{key_name}.pub", perms.PUBLIC_KEY_MODE)
        shutil.rmtree(staging)

        # revoke the old public key from each target (best-effort)
        for host, tr in zip(hosts, results, strict=True):
            provider = resolve_provider(host.provider, self._paths.providers)
            old_tgt = Target(
                alias=host.alias, hostname=host.hostname, user=host.user, port=host.port,
                pubkey_path=old_dir / f"{key_name}.pub", pubkey_text=old_pub_text,
                token_env=host.token_env, known_hosts=pdir / "known_hosts",
            )
            tr.revoked = provider.remove(old_tgt)

        self._update_inventory(profile, key_name, report, results)
        report.committed = True
        log.audit(self._paths.audit_log, "rotate",
                  key=key_name, old=report.old_fingerprint, new=report.new_fingerprint)
        return report

    def _update_inventory(self, profile: str, key_name: str,
                          report: RotateReport, results: list[TargetResult]) -> None:
        ident = str(self._manifest.identity_file(profile, key_name))
        old_ident = f"~/.ssh/profiles/{profile}/old/{key_name}"
        # Drop any stale record still pointing at the single /old/ slot (a prior
        # rotation's predecessor, now purged from disk) so records don't pile up.
        for fp in [f for f, r in self._inventory.keys.items()
                   if r.path == old_ident and f != report.old_fingerprint]:
            del self._inventory.keys[fp]
        # Keep the outgoing record but mark it archived (path -> old/), so rollback
        # can find it and expiry skips it.
        if report.old_fingerprint in self._inventory.keys:
            self._inventory.keys[report.old_fingerprint].path = old_ident
        created = today()
        self._inventory.record(report.new_fingerprint, KeyRecord(
            profile=profile, path=ident, type=self._manifest.defaults.key_type,
            comment=f"{profile}/{key_name} {created}", created=created,
            rotate_after_days=self._manifest.defaults.rotate_after_days,
            expires_on=compute_expiry(created, self._manifest.defaults.rotate_after_days),
            deployments=[
                Deployment(target=t.alias, method=t.provider, date=created,
                           verified=t.verified)
                for t in results
            ],
        ))

    # rollback
    def rollback(self, key_name: str) -> RotateReport:
        profile, hosts = self._profile_and_hosts(key_name)
        pdir = self._dir(profile)
        old_priv, old_pub = pdir / "old" / key_name, pdir / "old" / f"{key_name}.pub"
        if not old_priv.exists():
            raise SshManagerError(f"no /old/ predecessor to roll back to for {key_name!r}")
        cur_priv, cur_pub = pdir / key_name, pdir / f"{key_name}.pub"

        report = RotateReport(key_name=key_name)
        report.old_fingerprint = (
            self._keystore.fingerprint(cur_pub) if cur_pub.exists() else ""
        )
        cur_pub_text = cur_pub.read_text(encoding="utf-8") if cur_pub.exists() else ""
        report.new_fingerprint = self._keystore.fingerprint(old_pub)  # the restored key

        # Plain reverse move: predecessor -> canonical (replacing current).
        cur_priv.unlink(missing_ok=True)
        cur_pub.unlink(missing_ok=True)
        old_priv.replace(cur_priv)
        old_pub.replace(cur_pub)
        self._platform.set_perms(cur_priv, perms.PRIVATE_KEY_MODE)
        self._platform.set_perms(cur_pub, perms.PUBLIC_KEY_MODE)

        # Re-deploy the restored key + revoke the (removed) rotated-in key.
        results: list[TargetResult] = []
        for host in hosts:
            provider = resolve_provider(host.provider, self._paths.providers)
            tr = TargetResult(alias=host.alias, provider=provider.name)
            # The local restore above is the part that matters; the network
            # re-deploy/revoke is best-effort, so skip (don't hang on) an
            # unreachable host rather than aborting the rollback.
            if provider.category == "server" and not net.check(
                    host.hostname, host.port, ssh=True,
                    requires_vpn=host.requires_vpn, vpn_name=host.vpn_name).reachable:
                results.append(tr)
                continue
            restored = Target(
                alias=host.alias, hostname=host.hostname, user=host.user, port=host.port,
                pubkey_path=cur_pub, pubkey_text=cur_pub.read_text(encoding="utf-8"),
                token_env=host.token_env, identity_path=cur_priv,
                known_hosts=pdir / "known_hosts",
            )
            out = provider.deploy(restored)
            # Same semantics as rotate: "deployed" == an automated deploy that
            # succeeded OR a manual target (the user pastes it).
            tr.deployed = out.method == "manual" or out.verified
            tr.verified = provider.verify(restored)
            if cur_pub_text:
                removed = Target(
                    alias=host.alias, hostname=host.hostname, user=host.user,
                    port=host.port, pubkey_path=cur_pub, pubkey_text=cur_pub_text,
                    token_env=host.token_env, known_hosts=pdir / "known_hosts",
                )
                tr.revoked = provider.remove(removed)
            results.append(tr)
        report.targets = results

        # Inventory: drop the rotated-in record; restore the predecessor to canonical.
        if report.old_fingerprint:
            self._inventory.keys.pop(report.old_fingerprint, None)
        ident = str(self._manifest.identity_file(profile, key_name))
        if report.new_fingerprint in self._inventory.keys:
            self._inventory.keys[report.new_fingerprint].path = ident
            self._inventory.keys[report.new_fingerprint].deployments = [
                Deployment(target=t.alias, method=t.provider, date=today(),
                           verified=t.verified)
                for t in results
            ]
        report.committed = True
        log.audit(self._paths.audit_log, "rollback",
                  key=key_name, restored=report.new_fingerprint)
        return report
