"""Reconcile manifest -> reality. Idempotent, non-destructive.

Rebuilds the ~/.ssh tree, mints missing keys (flagged ``needs-redeploy`` - never
pretending a regenerated key is the lost original), re-renders config through the
ONE renderer, fixes perms, and validates with ``ssh -G``. Snapshots first
(invariant 10) and never clobbers an existing private key (invariant 15).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.inventory import Inventory, KeyRecord, compute_expiry, today
from ..core.manifest import Manifest, ResolvedKey
from ..platforms.base import Platform
from ..util import fs, log, perms
from ..util.paths import Paths
from .configsvc import ConfigService, WriteResult
from .keystore import KeyStore


@dataclass
class MintedKey:
    key_name: str
    profile: str
    fingerprint: str
    path: str


@dataclass
class ReconcileResult:
    dry_run: bool = False
    minted: list[MintedKey] = field(default_factory=list)
    existing_keys: list[str] = field(default_factory=list)
    config: WriteResult | None = None
    perms_fixed: int = 0
    snapshot: str | None = None
    validation_errors: dict[str, str] = field(default_factory=dict)
    pinned: dict[str, int] = field(default_factory=dict)   # profile -> host keys auto-pinned

    def format(self) -> str:
        verb = "would" if self.dry_run else "did"
        lines = [f"reconcile ({'dry-run' if self.dry_run else 'applied'}):"]
        if self.snapshot:
            lines.append(f"  snapshot: {self.snapshot}")
        for m in self.minted:
            lines.append(f"  mint {verb}: {m.key_name}  {m.fingerprint}  (needs-redeploy)")
        if not self.minted:
            lines.append(f"  keys: all {len(self.existing_keys)} present (none minted)")
        if self.config:
            c = self.config
            if c.written:
                lines.append(f"  config {verb} write: {', '.join(c.written)}")
            if c.pruned:
                lines.append(f"  config {verb} prune: {', '.join(c.pruned)}")
            if not c.written and not c.pruned:
                lines.append("  config: already in sync")
        if not self.dry_run:
            lines.append(f"  perms fixed on {self.perms_fixed} paths")
        if self.pinned:
            pretty = ", ".join(f"{p}={n}" for p, n in sorted(self.pinned.items()))
            lines.append(f"  host keys auto-pinned: {pretty}")
        for alias, err in self.validation_errors.items():
            lines.append(f"  ssh -G {alias}: {err}")
        return "\n".join(lines)


class Reconciler:
    def __init__(self, platform: Platform, paths: Paths, manifest: Manifest,
                 inventory: Inventory) -> None:
        self._platform = platform
        self._paths = paths
        self._manifest = manifest
        self._inventory = inventory
        self._keystore = KeyStore(platform)
        self._configsvc = ConfigService(platform, paths, manifest)

    def _priv_path(self, profile: str, key_name: str) -> Path:
        return self._paths.ssh_dir / "profiles" / profile / key_name

    def reconcile(self, *, dry_run: bool = False, passphrase: str = "") -> ReconcileResult:
        res = ReconcileResult(dry_run=dry_run)

        # 1. Plan key work (non-destructive: only mint what's missing).
        to_mint, existing = self._plan_mint(None)
        res.existing_keys = [rk.key_name for rk in existing]

        if dry_run:
            for rk in to_mint:
                res.minted.append(MintedKey(
                    rk.key_name, rk.profile, "(new)",
                    str(self._priv_path(rk.profile, rk.key_name)),
                ))
            res.config = self._configsvc.write(dry_run=True)
            return res

        # 2. (Snapshot + temp-residue sweep happen in the Facade mutation guard
        #     before we get here, so every mutating verb is covered uniformly.)

        # 3. Build the tree + mint missing keys, record them as needs-redeploy.
        self._ensure_tree()
        res.minted = [self._mint_one(rk, passphrase) for rk in to_mint]
        if to_mint:
            self._inventory.save(self._paths.inventory)

        # 4. Render config through the ONE renderer + write atomically.
        res.config = self._configsvc.write(dry_run=False)

        # 5. Fix perms on tool-managed paths (load-bearing; scoped so it never
        #    chmods unrelated files a user keeps in ~/.ssh).
        res.perms_fixed = self._fix_perms()

        # 6. Validate resolved config with ssh -G (best-effort report).
        res.validation_errors = self._configsvc.check(validate_ssh=True).ssh_errors

        log.audit(self._paths.audit_log, "reconcile",
                  minted=len(res.minted), config_written=len(res.config.written))
        return res

    def existing_keys(self, selector: str | None = None) -> list[str]:
        """Key names that already have a private key on disk (for the keygen
        overwrite/skip warning). Deduped + filtered to ``selector``."""
        _, existing = self._plan_mint(selector)
        return [rk.key_name for rk in existing]

    def mint(self, selector: str | None = None, *, passphrase: str = "",
             overwrite: set[str] | None = None) -> list[MintedKey]:
        """Targeted key generation (the `keygen` primitive): mint missing keys for
        a profile or host alias (all if None), plus regenerate any whose name is in
        ``overwrite`` (destructive - the Facade snapshots ~/.ssh first). No render."""
        overwrite = overwrite or set()
        to_mint, existing = self._plan_mint(selector)
        minted = [self._mint_one(rk, passphrase) for rk in to_mint]
        minted += [self._mint_one(rk, passphrase, overwrite=True)
                   for rk in existing if rk.key_name in overwrite]
        if minted:
            self._inventory.save(self._paths.inventory)
            self._fix_perms()
        return minted

    # shared mint helpers (reused by reconcile + keygen)
    def _plan_mint(self, selector: str | None) -> tuple[list[ResolvedKey], list[ResolvedKey]]:
        """Return (resolved-keys-to-mint, resolved-keys-already-present), deduped by
        path and filtered to ``selector`` (a profile name or host alias) when given."""
        to_mint: list[ResolvedKey] = []
        existing: list[ResolvedKey] = []
        seen: set[Path] = set()
        for rk in self._manifest.iter_resolved():
            if selector and selector not in (rk.profile, rk.host.alias):
                continue
            priv = self._priv_path(rk.profile, rk.key_name)
            if priv in seen:
                continue
            seen.add(priv)
            (existing if priv.exists() else to_mint).append(rk)
        return to_mint, existing

    def _ensure_tree(self) -> None:
        ssh = self._paths.ssh_dir
        fs.ensure_dir(ssh, perms.DIR_MODE)
        fs.ensure_dir(ssh / "profiles", perms.DIR_MODE)
        for pname in self._manifest.non_empty_profiles():
            fs.ensure_dir(ssh / "profiles" / pname, perms.DIR_MODE)

    def _mint_one(self, rk: ResolvedKey, passphrase: str = "",
                  *, overwrite: bool = False) -> MintedKey:
        priv = self._priv_path(rk.profile, rk.key_name)
        fs.ensure_dir(priv.parent, perms.DIR_MODE)
        comment = f"{rk.profile}/{rk.host.alias} {today()}"
        gen = self._keystore.generate(
            priv, key_type=self._manifest.defaults.key_type, comment=comment,
            passphrase=passphrase, overwrite=overwrite,
        )
        created = today()
        # Drop any stale inventory entry at this path (an old fingerprint left
        # behind when the previous key was deleted) so we never orphan it.
        ident = str(self._manifest.identity_file(rk.profile, rk.key_name))
        for fp in [fp for fp, rec in self._inventory.keys.items()
                   if rec.path == ident and fp != gen.fingerprint]:
            del self._inventory.keys[fp]
        self._inventory.record(gen.fingerprint, KeyRecord(
            profile=rk.profile,
            path=ident,
            type=self._manifest.defaults.key_type,
            comment=comment,
            created=created,
            rotate_after_days=self._manifest.defaults.rotate_after_days,
            expires_on=compute_expiry(created, self._manifest.defaults.rotate_after_days),
            deployments=[],  # empty == needs-redeploy
        ))
        log.audit(self._paths.audit_log, "keygen",
                  key=rk.key_name, fingerprint=gen.fingerprint, profile=rk.profile)
        return MintedKey(rk.key_name, rk.profile, gen.fingerprint, str(priv))

    def _fix_perms(self) -> int:
        count = 0
        for path, mode in perms.iter_managed_paths(self._paths.ssh_dir):
            self._platform.set_perms(path, mode)
            count += 1
        return count
