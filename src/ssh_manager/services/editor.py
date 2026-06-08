"""Manifest editing - profile/host add·edit·delete.

Edits go through the manifest (never a hand-edited config); each mutation is
validated, written atomically under the advisory lock, and audited. Delete
follows the §13 semantics: optionally revoke the deployed public key from its
tracked targets, then prune the inventory entry - so no orphaned access or
dangling deployment record is left behind.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.inventory import Inventory
from ..core.manifest import Host, Manifest, Profile
from ..platforms.base import Platform
from ..providers.base import Target
from ..providers.registry import resolve as resolve_provider
from ..util import log
from ..util.errors import SshManagerError
from ..util.lock import advisory_lock
from ..util.paths import Paths


@dataclass
class DeleteResult:
    removed: str
    revoked: list[str] = field(default_factory=list)
    pruned_keys: list[str] = field(default_factory=list)

    def format(self) -> str:
        lines = [f"deleted {self.removed}"]
        if self.revoked:
            lines.append(f"  revoked from: {', '.join(self.revoked)}")
        if self.pruned_keys:
            lines.append(f"  pruned inventory: {', '.join(self.pruned_keys)}")
        lines.append("  run `sshmgr reconcile` to re-render; local key files (if any) "
                     "are left in place (doctor flags them as orphaned).")
        return "\n".join(lines)


class ManifestEditor:
    def __init__(self, platform: Platform, paths: Paths) -> None:
        self._platform = platform
        self._paths = paths

    def _load(self) -> Manifest:
        return Manifest.load(self._paths.manifest)

    def _save(self, manifest: Manifest) -> None:
        # round-trip through validation so a bad edit can't be persisted
        validated = Manifest.model_validate(manifest.model_dump(mode="json"))
        validated.save(self._paths.manifest)

    # profiles
    def add_profile(self, name: str, *, key_scope: str = "per_service",
                    key_name: str | None = None) -> None:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            if name in m.profiles:
                raise SshManagerError(f"profile {name!r} already exists")
            m.profiles[name] = Profile(key_scope=key_scope, key_name=key_name)
            self._save(m)
            log.audit(self._paths.audit_log, "profile.add", profile=name)

    def edit_profile(self, name: str, *, key_scope: str | None = None,
                     key_name: str | None = None) -> None:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            if name not in m.profiles:
                raise SshManagerError(f"unknown profile: {name!r}")
            p = m.profiles[name]
            m.profiles[name] = Profile(
                key_scope=key_scope or p.key_scope,
                key_name=key_name if key_name is not None else p.key_name,
                hosts=p.hosts,
            )
            self._save(m)
            log.audit(self._paths.audit_log, "profile.edit", profile=name)

    def delete_profile(self, name: str, *, revoke: bool) -> DeleteResult:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            if name not in m.profiles:
                raise SshManagerError(f"unknown profile: {name!r}")
            inv = Inventory.load(self._paths.inventory)
            res = DeleteResult(removed=f"profile {name}")
            affected: set[str] = set()
            for host in list(m.profiles[name].hosts):
                key_name = m.resolved_key_name(name, host)
                affected.add(str(m.identity_file(name, key_name)))
                self._revoke_host(m, inv, name, host, revoke, res)
            del m.profiles[name]
            self._prune_idents(m, inv, affected, res)
            self._save(m)
            inv.save(self._paths.inventory)
            log.audit(self._paths.audit_log, "profile.delete", profile=name, revoke=revoke)
            return res

    # hosts
    def add_host(self, profile: str, alias: str, *, hostname: str, user: str,
                 port: int = 22, provider: str | None = None,
                 token_env: str | None = None, key_name: str | None = None,
                 tags: list[str] | None = None) -> None:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            if profile not in m.profiles:
                raise SshManagerError(f"unknown profile: {profile!r}")
            if any(h.alias == alias for h in m.profiles[profile].hosts):
                raise SshManagerError(f"host {alias!r} already exists in {profile!r}")
            m.profiles[profile].hosts.append(Host(
                alias=alias, hostname=hostname, user=user, port=port,
                provider=provider, token_env=token_env, key_name=key_name,
                tags=tags or [],
            ))
            self._save(m)
            log.audit(self._paths.audit_log, "host.add", profile=profile, alias=alias)

    def edit_host(self, profile: str, alias: str, *, hostname: str | None = None,
                  user: str | None = None, port: int | None = None,
                  provider: str | None = None, token_env: str | None = None,
                  key_name: str | None = None) -> None:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            host = self._find_host(m, profile, alias)
            new = host.model_copy(update={
                k: v for k, v in {
                    "hostname": hostname, "user": user, "port": port,
                    "provider": provider, "token_env": token_env, "key_name": key_name,
                }.items() if v is not None
            })
            hosts = m.profiles[profile].hosts
            hosts[hosts.index(host)] = new
            self._save(m)
            log.audit(self._paths.audit_log, "host.edit", profile=profile, alias=alias)

    def delete_host(self, profile: str, alias: str, *, revoke: bool) -> DeleteResult:
        with advisory_lock(self._paths.lock_file):
            m = self._load()
            host = self._find_host(m, profile, alias)
            inv = Inventory.load(self._paths.inventory)
            res = DeleteResult(removed=f"host {alias} (profile {profile})")
            key_name = m.resolved_key_name(profile, host)
            affected = {str(m.identity_file(profile, key_name))}
            self._revoke_host(m, inv, profile, host, revoke, res)
            m.profiles[profile].hosts.remove(host)
            self._prune_idents(m, inv, affected, res)
            self._save(m)
            inv.save(self._paths.inventory)
            log.audit(self._paths.audit_log, "host.delete",
                      profile=profile, alias=alias, revoke=revoke)
            return res

    # helpers
    def _find_host(self, m: Manifest, profile: str, alias: str) -> Host:
        if profile not in m.profiles:
            raise SshManagerError(f"unknown profile: {profile!r}")
        for h in m.profiles[profile].hosts:
            if h.alias == alias:
                return h
        raise SshManagerError(f"unknown host {alias!r} in profile {profile!r}")

    def _revoke_host(self, m: Manifest, inv: Inventory, profile: str,
                     host: Host, revoke: bool, res: DeleteResult) -> None:
        """Revoke this host's key from its OWN target (if it was deployed there) and
        drop this host's deployment entry from the inventory record. The record
        itself is pruned later by _prune_idents, only once no surviving manifest
        host still uses the key - so a key shared across hosts isn't torn out from
        under the hosts that remain, and every deleted host is revoked (not just
        the first)."""
        key_name = m.resolved_key_name(profile, host)
        ident = str(m.identity_file(profile, key_name))
        for rec in [r for r in inv.keys.values() if r.path == ident]:
            if (revoke and any(d.target == host.alias for d in rec.deployments)
                    and self._remove_from_target(profile, key_name, host)):
                res.revoked.append(host.alias)
            rec.deployments = [d for d in rec.deployments if d.target != host.alias]

    def _prune_idents(self, m: Manifest, inv: Inventory, affected: set[str],
                      res: DeleteResult) -> None:
        """Drop inventory records for the affected key paths that no surviving
        manifest host references any more (scoped to the deletion - never touches
        unrelated records or archived /old/ predecessors)."""
        used = {
            str(m.identity_file(p, m.resolved_key_name(p, h)))
            for p, prof in m.profiles.items() for h in prof.hosts
        }
        for fp in [f for f, rec in inv.keys.items()
                   if rec.path in affected and rec.path not in used]:
            res.pruned_keys.append(inv.keys[fp].path.rsplit("/", 1)[-1])
            del inv.keys[fp]

    def _remove_from_target(self, profile: str, key_name: str, host: Host) -> bool:
        pub = self._paths.ssh_dir / "profiles" / profile / f"{key_name}.pub"
        pub_text = pub.read_text(encoding="utf-8") if pub.exists() else ""
        provider = resolve_provider(host.provider, self._paths.providers)
        tgt = Target(
            alias=host.alias, hostname=host.hostname, user=host.user,
            port=host.port, pubkey_path=pub, pubkey_text=pub_text,
            token_env=host.token_env,
            known_hosts=self._paths.ssh_dir / "profiles" / profile / "known_hosts",
        )
        return provider.remove(tgt)
