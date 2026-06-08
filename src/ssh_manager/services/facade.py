"""SshManagerService - the single Facade.

CLI, TUI, and the future desktop app all call this; no surface reimplements
logic. Wires the core models + service objects + platform strategy, and runs all
state mutations under the advisory lock (invariant 11).
"""
from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..core.authorized_keys import is_valid_public_key, key_body
from ..core.expiry import ExpiryStatus
from ..core.inventory import Inventory
from ..core.manifest import Manifest
from ..platforms import detect
from ..platforms.base import Platform
from ..util import fs, log, net, perms, proc
from ..util.errors import ManifestError, SshManagerError
from ..util.lock import advisory_lock
from ..util.paths import Paths, load_env, resolve_paths
from .agent import Agent
from .bundler import AgeCipher, Bundler, BundleResult, Cipher, RestoreResult
from .configsvc import ConfigCheckResult, ConfigService, WriteResult
from .deployer import Deployer, DeployReport
from .editor import DeleteResult, ManifestEditor
from .importer import Importer, ImportResult
from .keystore import KeyStore
from .knownhosts import KnownHostsService, ScannedKey
from .notifier import Notifier
from .preflight import Report, check, format_report
from .query import HostDetail, ProfileGroup, ProfileSummary, Query
from .reconciler import MintedKey, Reconciler, ReconcileResult
from .rotator import RotateReport, Rotator

SNAPSHOT_RETAIN = 10

# Config-dir state whose perms are security-sensitive.
SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700


@dataclass
class InitResult:
    config_dir: Path
    created: list[str] = field(default_factory=list)
    existed: list[str] = field(default_factory=list)
    backup: Path | None = None

    def format(self) -> str:
        lines = [f"init: home {self.config_dir}"]
        for c in self.created:
            lines.append(f"  created  {c}")
        for e in self.existed:
            lines.append(f"  exists   {e} (left as-is)")
        if self.backup is not None:
            lines.append(f"  backup   previous files saved to {self.backup}")
        lines.append(f"Next: edit {self.config_dir / 'manifest.json'}, then `sshmgr reconcile`.")
        return "\n".join(lines)


@dataclass
class KeyCheck:
    """Result of validating one managed keypair (see SshManagerService.validate_keys)."""
    key_name: str
    profile: str
    fingerprint: str | None = None
    ok: bool = True
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # informational, not failures


@dataclass
class ProviderInfo:
    """A configured provider and whether its credential is present right now."""
    name: str
    kind: str
    category: str
    token_env: str | None
    token_present: bool


@dataclass
class HostNet:
    """A host's network reachability (for the `net` status indicator)."""
    profile: str
    alias: str
    status: net.NetStatus


@dataclass
class MigrateResult:
    """Outcome of `sshmgr migrate` (legacy ~/.sshmgr -> standard home)."""
    moved: bool
    legacy: Path
    home: Path
    backup: Path | None = None
    message: str = ""

    def format(self) -> str:
        return self.message


@dataclass
class HostPinResult:
    """Outcome of initializing one host's entry in its profile's known_hosts."""
    profile: str
    alias: str
    hostname: str
    port: int
    status: str           # pinned | already-trusted | unreachable | no-keys
    fingerprints: list[str] = field(default_factory=list)


@dataclass
class KnownHostsInitReport:
    profiles: list[str] = field(default_factory=list)   # profiles whose file was ensured
    created: list[str] = field(default_factory=list)     # known_hosts files newly created
    results: list[HostPinResult] = field(default_factory=list)

    def format(self) -> str:
        lines = [f"knownhosts init: {len(self.profiles)} profile(s)"]
        for c in self.created:
            lines.append(f"  created {c}")
        by_profile: dict[str, list[HostPinResult]] = {}
        for r in self.results:
            by_profile.setdefault(r.profile, []).append(r)
        icon = {"pinned": "+", "already-trusted": "=", "unreachable": "!", "no-keys": "?"}
        for prof in sorted(by_profile):
            lines.append(f"  [{prof}]")
            for r in by_profile[prof]:
                lines.append(f"    {icon.get(r.status, ' ')} {r.alias} ({r.hostname}:{r.port}) "
                             f"- {r.status}")
                lines.extend(f"        {fp}" for fp in r.fingerprints)
        pinned = sum(1 for r in self.results if r.status == "pinned")
        unreachable = [r.alias for r in self.results if r.status == "unreachable"]
        tail = f"; unreachable (pin later): {', '.join(unreachable)}" if unreachable else ""
        lines.append(f"  pinned {pinned} host(s){tail}")
        lines.append("  review fingerprints above; use `sshmgr knownhosts pin` to "
                     "confirm-before-trust.")
        return "\n".join(lines)


@dataclass
class DoctorReport:
    preflight: Report
    home: Path | None = None          # the resolved ssh-manager home (OS-standard dir or override)
    ssh_dir: Path | None = None
    perm_issues: list[str] = field(default_factory=list)
    agent_status: str = ""
    known_hosts: bool = False
    old_keys: dict[str, int] = field(default_factory=dict)  # key_name -> archived count
    config_in_sync: bool = True
    orphan_keys: list[str] = field(default_factory=list)     # on disk, not in manifest
    duplicate_keys: list[str] = field(default_factory=list)  # share a fingerprint (reuse)
    unpinned_hosts: list[str] = field(default_factory=list)  # manifest hosts lacking a pinned key
    alias_collisions: list[str] = field(default_factory=list)  # same alias in >1 profile
    providers_source: str = "shipped default"   # "user file" | "shipped default"
    stranded_legacy_home: Path | None = None     # a ~/.sshmgr that wasn't migrated

    @property
    def ok(self) -> bool:
        return (
            self.preflight.ok
            and not self.perm_issues
            and self.config_in_sync
            and all(n <= 1 for n in self.old_keys.values())
        )

    def as_dict(self) -> dict[str, object]:
        """JSON-serializable view for `doctor --json` (scripting / monitoring)."""
        return {
            "ok": self.ok,
            "home": str(self.home) if self.home else None,
            "ssh_dir": str(self.ssh_dir) if self.ssh_dir else None,
            "providers_source": self.providers_source,
            "preflight_ok": self.preflight.ok,
            "agent": self.agent_status,
            "known_hosts": self.known_hosts,
            "config_in_sync": self.config_in_sync,
            "perm_issues": self.perm_issues,
            "old_keys": self.old_keys,
            "orphan_keys": self.orphan_keys,
            "duplicate_keys": self.duplicate_keys,
            "unpinned_hosts": self.unpinned_hosts,
            "alias_collisions": self.alias_collisions,
            "stranded_legacy_home":
                str(self.stranded_legacy_home) if self.stranded_legacy_home else None,
        }

    def format(self) -> str:
        lines = [format_report(self.preflight), ""]
        if self.home is not None:
            lines.append(f"home: {self.home}  (config + secrets + logs + snapshots live here)")
        if self.ssh_dir is not None:
            lines.append(f"ssh:  {self.ssh_dir}  (generated)")
        lines.append(f"providers: {self.providers_source}")
        if self.stranded_legacy_home is not None:
            lines.append(f"WARNING: a legacy home {self.stranded_legacy_home} was NOT "
                         "migrated (the standard home already existed). Compare the two, "
                         "then run `sshmgr migrate --force` (backs up the current home "
                         "and replaces it with the legacy one).")
        lines.append(f"agent: {self.agent_status}")
        lines.append(f"known_hosts: {'present' if self.known_hosts else 'absent'}")
        if self.unpinned_hosts:
            # Per-profile UserKnownHostsFile + the OpenSSH default
            # StrictHostKeyChecking=ask means a host with no pinned key fails
            # non-interactive ssh/git with "Host key verification failed".
            lines.append("host keys NOT pinned (ssh/git will fail host-key "
                         "verification until these are pinned):")
            lines.extend(f"  {h}" for h in self.unpinned_hosts)
            lines.append("  -> run: sshmgr knownhosts pin --all   "
                         "(VPN-gated hosts: connect the VPN first)")
        if self.alias_collisions:
            lines.append("WARNING: the same Host alias is used in >1 profile - ssh "
                         "applies the FIRST match, so the others are shadowed:")
            lines.extend(f"  {a}" for a in self.alias_collisions)
            lines.append("  -> give each host a distinct, profile-prefixed alias")
        drift = "none" if self.config_in_sync else "DRIFT (run config render)"
        lines.append(f"config drift: {drift}")
        if self.perm_issues:
            lines.append("perm issues:")
            lines.extend(f"  {p}" for p in self.perm_issues)
        else:
            lines.append("perms: ok")
        bad_old = {p: n for p, n in self.old_keys.items() if n > 1}
        if bad_old:
            lines.append("WARNING: >1 archived predecessor (invariant ≤1-old): "
                         + ", ".join(f"{p}={n}" for p, n in bad_old.items()))
        if self.orphan_keys:
            lines.append("orphaned keys (on disk, not in the manifest):")
            lines.extend(f"  {k}" for k in self.orphan_keys)
        if self.duplicate_keys:
            lines.append("WARNING: keys reuse the same fingerprint (blast radius): "
                         + ", ".join(self.duplicate_keys))
        lines.append("")
        lines.append("doctor: " + ("clean ✓" if self.ok else "issues found"))
        return "\n".join(lines)


class SshManagerService:
    def __init__(self, *, cwd: Path | None = None,
                 env: dict[str, str] | None = None,
                 ssh_dir: Path | None = None,
                 platform: Platform | None = None) -> None:
        self.platform: Platform = platform or detect()
        self.paths: Paths = resolve_paths(self.platform, env=env, cwd=cwd, ssh_dir=ssh_dir)
        self._migrate_legacy_home(env)
        load_env(self.paths.env_file)
        self.snapshot_retain = _int_env("SSH_MANAGER_SNAPSHOT_RETAIN", SNAPSHOT_RETAIN)

    def _legacy_homes(self) -> list[Path]:
        """Pre-rename / pre-XDG home locations, in priority order. The product was
        renamed ``sshmgr`` -> ``ssh-manager``, so the old OS-standard folder is the
        ``sshmgr`` sibling of the new home (``~/.config/sshmgr``, ``%APPDATA%\\sshmgr``);
        the original dot-home ``~/.sshmgr`` predates the XDG layout."""
        return [self.paths.config_dir.with_name("sshmgr"), Path.home() / ".sshmgr"]

    def _first_legacy_home(self, new: Path) -> Path | None:
        """First real legacy dir worth migrating (not the new home, not a symlink)."""
        for cand in self._legacy_homes():
            if cand != new and cand.is_dir() and not cand.is_symlink():
                return cand
        return None

    def _migrate_legacy_home(self, env: dict[str, str] | None) -> None:
        """One-time move of a legacy home (``~/.config/sshmgr`` from before the
        rename, or the older ``~/.sshmgr``) to the OS-standard config dir
        (``~/.config/ssh-manager`` etc.). Runs only when the location wasn't
        overridden ($SSH_MANAGER_HOME/$SSH_MANAGER_CONFIG_DIR), the new dir doesn't exist yet,
        and a legacy dir is a real directory.

        Race-safe: the cheap pre-check avoids the lock on the common (already-migrated)
        path, then it serializes under an advisory lock and re-checks the destination
        *after* acquiring it - and uses ``os.rename`` (which fails rather than nesting
        the legacy dir inside an existing destination). A genuine failure is surfaced
        to stderr (and left for ``doctor`` to flag) rather than silently stranding the
        user's real config in the legacy home."""
        source = os.environ if env is None else env
        if source.get("SSH_MANAGER_HOME") or source.get("SSH_MANAGER_CONFIG_DIR"):
            return
        new = self.paths.config_dir
        if new.exists():
            return
        legacy = self._first_legacy_home(new)
        if legacy is None:
            return
        new.parent.mkdir(parents=True, exist_ok=True)
        lock_path = new.with_name(new.name + ".migrate.lock")
        try:
            with advisory_lock(lock_path):
                if new.exists() or not legacy.is_dir():   # re-check under the lock
                    return
                try:
                    os.rename(legacy, new)   # atomic same-fs; errors (no nesting) if dest exists
                except OSError:
                    shutil.move(str(legacy), str(new))   # cross-fs (EXDEV); dest is absent here
        except OSError as exc:
            if legacy.exists() and not new.exists():
                print(f"ssh-manager: could not migrate legacy {legacy} to {new}: {exc}; "
                      "move it manually or set SSH_MANAGER_HOME", file=sys.stderr)
        finally:
            with contextlib.suppress(OSError):
                lock_path.unlink()

    def migrate_home(self, *, force: bool = False) -> MigrateResult:
        """Explicitly migrate a legacy home (``~/.config/sshmgr`` from before the
        rename, or the older ``~/.sshmgr``) to the standard home - the guided path
        for the case auto-migration can't handle (both already exist). If the
        standard home is absent, the legacy is moved in. If BOTH exist, refuse
        unless ``force``; with ``force`` the current standard home is backed up aside
        and replaced with the legacy one (so the legacy data wins, nothing is lost)."""
        home = self.paths.config_dir
        legacy = self._first_legacy_home(home)
        if legacy is None:
            return MigrateResult(False, self.paths.config_dir.with_name("sshmgr"), home,
                                 message=f"no legacy home to migrate (home: {home})")
        if legacy.resolve() == home.resolve():
            return MigrateResult(False, legacy, home, message=f"already at the home: {home}")
        home.parent.mkdir(parents=True, exist_ok=True)
        lock_path = home.with_name(home.name + ".migrate.lock")
        try:
            with advisory_lock(lock_path):
                if not home.exists():
                    _move_dir(legacy, home)
                    return MigrateResult(True, legacy, home,
                                         message=f"migrated {legacy} -> {home}")
                if not force:
                    raise SshManagerError(
                        f"both {legacy} and {home} exist. Inspect them, then re-run "
                        "`sshmgr migrate --force` to back up the current home and "
                        "replace it with the legacy one.")
                backup = home.with_name(f"{home.name}.replaced-{datetime.now():%Y%m%d-%H%M%S}")
                os.rename(home, backup)
                _move_dir(legacy, home)
                return MigrateResult(True, legacy, home, backup=backup,
                                     message=(f"migrated {legacy} -> {home}; "
                                              f"previous home backed up to {backup}"))
        finally:
            with contextlib.suppress(OSError):
                lock_path.unlink()

    # lazy repositories
    def manifest(self) -> Manifest:
        return Manifest.load(self.paths.manifest)

    def inventory(self) -> Inventory:
        return Inventory.load(self.paths.inventory)

    # home setup (converge the per-user home)
    def init(self, *, force: bool = False, backup: bool = False) -> InitResult:
        """Create and converge the one per-user home (OS-standard ssh-manager dir). Every run
        (re)creates the directory scaffolding (config + log/ + snapshots/ + .state/)
        and re-asserts perms (secrets 600, dirs 700). Missing starter files are
        seeded. ``force`` *overwrites* the seed files (manifest/inventory/providers/
        .env) with fresh defaults. By default the old files are NOT kept; pass
        ``backup=True`` to first copy them into ``<home>/.state/init-backup-<ts>/``."""
        res = InitResult(config_dir=self.paths.config_dir)
        with advisory_lock(self.paths.lock_file):
            for d in (self.paths.config_dir, self.paths.log_dir,
                      self.paths.snapshots_dir, self.paths.dist_dir, self.paths.state_dir):
                fs.ensure_dir(d, SECRET_DIR_MODE)
            backup_dir = self._init_backup_dir() if (force and backup) else None
            self._seed(self.paths.manifest, res, lambda: Manifest.starter(
                emit_use_keychain=self.platform.emits_use_keychain
            ).save(self.paths.manifest), force=force, backup=backup_dir)
            self._seed(self.paths.inventory, res,
                       lambda: Inventory().save(self.paths.inventory),
                       force=force, backup=backup_dir)
            # providers.json is NOT seeded: the full catalog is read from the shipped
            # package default (always accurate); create <home>/providers.json only
            # to customize it (see registry._load_catalog).
            self._seed_env(res, force=force, backup=backup_dir)
            # always re-assert perms on whatever now exists
            for path, mode in self._secret_perms():
                if path.exists() and not self.platform.perms_ok(path, mode):
                    self.platform.set_perms(path, mode)
            if backup_dir is not None and backup_dir.exists():
                res.backup = backup_dir
        return res

    def _init_backup_dir(self) -> Path:
        return self.paths.state_dir / f"init-backup-{datetime.now():%Y%m%d-%H%M%S}"

    def _backup_file(self, path: Path, backup: Path | None) -> None:
        if backup is None or not path.exists():
            return
        fs.ensure_dir(backup, SECRET_DIR_MODE)
        shutil.copy2(path, backup / path.name)   # copy2 preserves the source mode

    def _should_write(self, path: Path, res: InitResult, *,
                      force: bool, backup: Path | None) -> bool:
        """Decide whether to (over)write a seed file; record + back up accordingly."""
        if path.exists():
            if not force:
                res.existed.append(path.name)
                return False
            self._backup_file(path, backup)
            note = "reset; backup saved" if backup is not None else "reset (no backup)"
            res.created.append(f"{path.name} ({note})")
            return True
        res.created.append(path.name)
        return True

    def _seed(self, path: Path, res: InitResult, make: Callable[[], None], *,
              force: bool = False, backup: Path | None = None) -> None:
        if self._should_write(path, res, force=force, backup=backup):
            make()

    def _seed_env(self, res: InitResult, *,
                  force: bool = False, backup: Path | None = None) -> None:
        if not self._should_write(self.paths.env_file, res, force=force, backup=backup):
            return
        example = self.paths.env_example
        if example.exists():
            text = example.read_text(encoding="utf-8")
        else:
            try:
                text = _read_data(".env-example")    # shipped template
            except (FileNotFoundError, OSError):
                text = _DEFAULT_ENV
        fs.write_text_atomic(self.paths.env_file, text, SECRET_FILE_MODE)

    # perms auto-fix (doctor verifies AND fixes)
    def fix_perms(self) -> list[str]:
        """Re-assert canonical perms on tool-managed ~/.ssh paths AND config-dir
        secrets. Returns the paths it changed."""
        changed: list[str] = []
        with advisory_lock(self.paths.lock_file):
            for path, mode in perms.iter_managed_paths(self.paths.ssh_dir):
                if not self.platform.perms_ok(path, mode):
                    self.platform.set_perms(path, mode)
                    changed.append(f"{path} -> {mode:o}")
            for path, mode in self._secret_perms():
                if path.exists() and not self.platform.perms_ok(path, mode):
                    self.platform.set_perms(path, mode)
                    changed.append(f"{path} -> {mode:o}")
        if changed:
            log.audit(self.paths.audit_log, "fix_perms", count=len(changed))
        return changed

    def _secret_perms(self) -> list[tuple[Path, int]]:
        p = self.paths
        items: list[tuple[Path, int]] = [
            (p.config_dir, SECRET_DIR_MODE),
            (p.log_dir, SECRET_DIR_MODE),
            (p.state_dir, SECRET_DIR_MODE),
            (p.snapshots_dir, SECRET_DIR_MODE),
            (p.dist_dir, SECRET_DIR_MODE),
            (p.env_file, SECRET_FILE_MODE),
            (p.age_identity, SECRET_FILE_MODE),
            (p.audit_log, SECRET_FILE_MODE),
            (p.lock_file, SECRET_FILE_MODE),
        ]
        # encrypted bundles (in dist/, and legacy ones left in the home root)
        items += [(age, SECRET_FILE_MODE) for age in p.dist_dir.glob("*.age")]
        items += [(age, SECRET_FILE_MODE) for age in p.config_dir.glob("*.age")]
        items += [(idf, SECRET_FILE_MODE) for idf in p.config_dir.glob("*-identity.txt")]
        # snapshot tarballs hold private keys - keep them owner-only too
        items += [(snap, SECRET_FILE_MODE) for snap in p.snapshots_dir.glob("ssh-*.tar.gz")]
        return items

    # auto-pin host keys per profile (called INSIDE an existing mutation lock)
    def _auto_pin(self, manifest: Manifest, profiles: set[str] | None) -> dict[str, int]:
        """Create/update each profile's known_hosts with its hosts' keys, so a freshly
        minted profile works without a separate `knownhosts pin`. Best-effort and safe:
        trust-on-first-use only (never overrides an already-pinned host, so a later real
        key change is NOT silently accepted), skips unreachable/VPN-gated hosts, and is
        disabled by ``SSH_MANAGER_AUTO_PIN`` set to 0/false/no/off. Does NOT take the lock (the
        caller holds it). Runs under the lock, so the reachability probe is kept short.
        Returns {profile: host keys added}. Use `knownhosts pin` for fingerprint-verified
        trust of hosts this can't reach.
        """
        if _auto_pin_disabled() or not proc.has("ssh-keyscan"):
            return {}
        khs = KnownHostsService(self.platform, self.paths.ssh_dir)
        added: dict[str, int] = {}
        seen: set[tuple[str, str, int]] = set()
        for rk in manifest.iter_resolved():
            if profiles is not None and rk.profile not in profiles:
                continue
            h = rk.host
            key = (rk.profile, h.hostname, h.port)
            if key in seen:
                continue
            seen.add(key)
            kh = self.paths.ssh_dir / "profiles" / rk.profile / "known_hosts"
            token = h.hostname if h.port == 22 else f"[{h.hostname}]:{h.port}"
            if _host_in_known_hosts(kh, token):
                continue                          # already trusted - never override
            # Short probe: this runs while holding the advisory lock, so a few
            # unreachable hosts mustn't stall every concurrent invocation for long.
            if not net.tcp_reachable(h.hostname, h.port, timeout=2):
                continue                          # unreachable/VPN-gated - pin later
            scanned = khs.scan(h.hostname, h.port)
            n = khs.add([sk.line for sk in scanned], rk.profile) if scanned else 0
            if n:
                added[rk.profile] = added.get(rk.profile, 0) + n
        if added:
            log.audit(self.paths.audit_log, "knownhosts.autopin", added=sum(added.values()))
        return added

    # mutation guard (clean-state, snapshot-before-mutate, lock)
    @contextlib.contextmanager
    def _mutating(self, label: str, *, snapshot: bool = True) -> Iterator[str | None]:
        """Run a mutating op under the lock, after sweeping crash residue and
        snapshotting ~/.ssh (the local reversible backup). Yields the snapshot
        path (or None). Every mutating verb passes through here so the clean-state
        + backup guarantee is uniform, not per-command (invariant 10)."""
        with advisory_lock(self.paths.lock_file):
            swept = fs.clean_temp_artifacts(self.paths.ssh_dir)
            snap: str | None = None
            if snapshot:
                made = fs.snapshot_ssh_dir(
                    self.paths.ssh_dir, self.paths.snapshots_dir, retain=self.snapshot_retain
                )
                snap = str(made) if made else None
            log.audit(self.paths.audit_log, f"{label}.begin",
                      snapshot=snap, swept=len(swept))
            yield snap

    # use-cases
    def reconcile(self, *, dry_run: bool = False, passphrase: str = "",
                  auto_pin: bool = True) -> ReconcileResult:
        if dry_run:
            manifest, inventory = self.manifest(), self.inventory()
            return Reconciler(
                self.platform, self.paths, manifest, inventory
            ).reconcile(dry_run=True)
        with self._mutating("reconcile") as snap:
            manifest, inventory = self.manifest(), self.inventory()
            res = Reconciler(self.platform, self.paths, manifest, inventory).reconcile(
                dry_run=False, passphrase=passphrase
            )
            res.snapshot = snap
            if auto_pin:
                # populate every profile's known_hosts so each one is usable
                res.pinned = self._auto_pin(manifest, None)
            return res

    def config_check(self) -> ConfigCheckResult:
        return ConfigService(self.platform, self.paths, self.manifest()).check()

    def config_render(self, *, dry_run: bool = False) -> WriteResult:
        if dry_run:
            return ConfigService(self.platform, self.paths, self.manifest()).write(
                dry_run=True
            )
        with self._mutating("config_render"):
            return ConfigService(self.platform, self.paths, self.manifest()).write(
                dry_run=False
            )

    def config_show(self, alias: str | None = None) -> str:
        return ConfigService(self.platform, self.paths, self.manifest()).show(alias)

    # keygen / load / audit
    def existing_keys(self, selector: str) -> list[str]:
        """Key names under ``selector`` that already have a private key on disk
        (so the CLI can warn before overwriting)."""
        manifest = self.manifest()
        self._require_selector(manifest, selector)
        return Reconciler(self.platform, self.paths, manifest,
                          self.inventory()).existing_keys(selector)

    def keygen(self, selector: str, *, passphrase: str = "",
               overwrite: set[str] | None = None, auto_pin: bool = True) -> list[MintedKey]:
        """Targeted key generation for a profile or host alias (the primitive).
        ``overwrite`` names keys to regenerate (destructive - ~/.ssh is snapshotted
        first by the mutation guard). After minting, the affected profiles'
        known_hosts are auto-pinned (best-effort) so the keys are usable."""
        manifest = self.manifest()
        self._require_selector(manifest, selector)
        with self._mutating("keygen"):
            inventory = self.inventory()
            minted = Reconciler(self.platform, self.paths, manifest, inventory).mint(
                selector, passphrase=passphrase, overwrite=overwrite)
            if auto_pin and minted:
                self._auto_pin(manifest, {m.profile for m in minted})
            return minted

    def _require_selector(self, manifest: Manifest, selector: str) -> None:
        known = set(manifest.profiles) | {
            h.alias for p in manifest.profiles.values() for h in p.hosts
        }
        if selector not in known:
            raise SshManagerError(f"unknown profile or host: {selector!r}")

    def load(self, profile: str) -> list[str]:
        """Add a profile's keys to the ssh-agent (keychain on macOS)."""
        manifest = self.manifest()
        if profile not in manifest.profiles:
            raise SshManagerError(f"unknown profile: {profile!r}")
        agent = Agent(use_keychain=self.platform.emits_use_keychain)
        added: list[str] = []
        seen: set[Path] = set()
        for rk in manifest.iter_resolved():
            if rk.profile != profile:
                continue
            priv = self.paths.ssh_dir / "profiles" / rk.profile / rk.key_name
            if priv in seen:          # a shared key maps to many hosts - add once
                continue
            seen.add(priv)
            if priv.exists() and agent.add(priv):
                added.append(rk.key_name)
        return added

    def audit(self, *, notify: bool = False) -> str:
        """Deployment + expiry + hygiene summary, plus recent activity. With
        ``notify`` it also fires the cadence-gated desktop alert (the scheduled
        job runs `sshmgr audit --notify`)."""
        now = datetime.now()
        inv = self.inventory()
        notifier = Notifier(self.platform, self.paths, self.manifest().defaults)
        lines = ["=== deployments ==="]
        if not inv.keys:
            lines.append("  (inventory empty - run reconcile, then deploy)")
        for fp, rec in inv.keys.items():
            status = "needs-redeploy" if rec.needs_redeploy else "deployed"
            lines.append(f"{rec.path}  [{status}]")
            lines.append(f"    {fp}")
            for d in rec.deployments:
                flag = "verified" if d.verified else "unverified"
                lines.append(f"    - {d.target} via {d.method} ({flag}) {d.date or ''}".rstrip())
        lines += ["", "=== expiry ==="]
        lines += self._expiry_lines(notifier.states(now=now))
        lines += ["", "=== recent activity ==="]
        lines += self._recent_audit(10) or ["  (no audit log yet)"]
        if notify:
            fired = notifier.notify(now=now)
            log.audit(self.paths.audit_log, "audit.notify", fired=fired)
            status = "sent" if fired else "not sent (not due, disabled, or no notifier backend)"
            lines += ["", f"desktop notification: {status}"]
        return "\n".join(lines)

    def expiry_states(self) -> list[ExpiryStatus]:
        """Per-key expiry status (data; rendering lives in ssh_manager.render)."""
        return Notifier(
            self.platform, self.paths, self.manifest().defaults
        ).states(now=datetime.now())

    def expiry_banner(self) -> str:
        """The cheap, debounced inline reminder (empty when nothing is due)."""
        try:
            return Notifier(
                self.platform, self.paths, self.manifest().defaults
            ).banner(now=datetime.now())
        except SshManagerError:
            return ""

    def notify_install(self) -> str:
        """Install the scheduled launchd/cron job that runs `sshmgr audit --notify`."""
        command = f"{self._scheduler_exe()} audit --notify"
        Notifier(self.platform, self.paths, self.manifest().defaults).install(command)
        log.audit(self.paths.audit_log, "notify.install", command=command)
        return command

    def _scheduler_exe(self) -> str:
        """Shell-quoted invocation for the scheduled job, so an install path with
        spaces stays one token. POSIX schedulers (launchd/cron/systemd) parse with
        shell rules -> shlex.quote; Windows schtasks /TR runs via cmd.exe, which
        treats single quotes literally -> double-quote instead."""
        win = self.platform.name == "windows"
        quote = (lambda s: f'"{s}"') if win else shlex.quote
        found = shutil.which("sshmgr")
        if found:
            return quote(found)
        return f"{quote(sys.executable)} -m ssh_manager.cli"

    def notify_test(self) -> bool:
        """Fire a test notification. Returns False if no notifier backend exists."""
        return Notifier(self.platform, self.paths, self.manifest().defaults).test()

    def _expiry_lines(self, states: list[ExpiryStatus]) -> list[str]:
        if not states:
            return ["  (nothing tracked)"]
        out = []
        for s in states:
            days = "?" if s.days_remaining is None else f"{s.days_remaining}d"
            out.append(f"  {s.key_name}  {s.state}  ({s.expires_on or '?'}, {days})")
        return out

    def _recent_audit(self, n: int) -> list[str]:
        if not self.paths.audit_log.exists():
            return []
        tail = self.paths.audit_log.read_text(encoding="utf-8").splitlines()[-n:]
        return [f"  {ln}" for ln in tail]

    # bundle / restore
    def bundle(self, *, recipient: str | None = None, output: Path | None = None,
               cipher: Cipher | None = None) -> BundleResult:
        """Encrypted backup of {keys + manifest + inventory + providers} (no .env)."""
        recip = recipient or os.environ.get("SSH_MANAGER_AGE_RECIPIENT", "")
        dest = output or self.paths.dist_dir
        dest.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        bundler = Bundler(self.paths.ssh_dir, self.paths.config_dir, cipher or AgeCipher())
        with advisory_lock(self.paths.lock_file):
            result = bundler.bundle(recipient=recip, dest_dir=dest, stamp=stamp)
        log.audit(self.paths.audit_log, "bundle",
                  path=str(result.age_path), files=len(result.contents))
        return result

    def restore(self, bundle_path: Path, *, identity_file: Path | None = None,
                passphrase: str | None = None,
                cipher: Cipher | None = None) -> RestoreResult:
        """Decrypt a bundle and lay the SAME keys back down (true recovery, §3).
        Snapshots ~/.ssh first (mutation guard), then fixes perms + re-renders."""
        ident = identity_file
        if ident is None:
            env_id = os.environ.get("SSH_MANAGER_AGE_IDENTITY_FILE")
            ident = Path(env_id).expanduser() if env_id else None
        keystore = KeyStore(self.platform)
        bundler = Bundler(self.paths.ssh_dir, self.paths.config_dir, cipher or AgeCipher())
        with self._mutating("restore"):
            res = bundler.restore(
                bundle_path, identity_file=ident, passphrase=passphrase,
                fingerprint_of=keystore.fingerprint,
            )
            for path, mode in perms.iter_managed_paths(self.paths.ssh_dir):
                self.platform.set_perms(path, mode)
            for path, mode in self._secret_perms():
                if path.exists():
                    self.platform.set_perms(path, mode)
            # re-render the config from the restored manifest so ~/.ssh is usable
            with contextlib.suppress(SshManagerError):
                ConfigService(self.platform, self.paths, self.manifest()).write()
        log.audit(self.paths.audit_log, "restore",
                  path=str(bundle_path), files=len(res.restored))
        return res

    # known_hosts pinning - per profile
    def known_hosts_targets(self) -> list[tuple[str, str, str, int]]:
        """(profile, alias, hostname, port) for every manifest host (deduped)."""
        seen: set[tuple[str, str, int]] = set()
        out: list[tuple[str, str, str, int]] = []
        for rk in self.manifest().iter_resolved():
            key = (rk.profile, rk.host.hostname, rk.host.port)
            if key in seen:
                continue
            seen.add(key)
            out.append((rk.profile, rk.host.alias, rk.host.hostname, rk.host.port))
        return out

    def profile_of_alias(self, alias: str) -> str | None:
        for rk in self.manifest().iter_resolved():
            if rk.host.alias == alias:
                return rk.profile
        return None

    def known_hosts_scan(self, hostname: str, port: int = 22) -> list[ScannedKey]:
        return KnownHostsService(self.platform, self.paths.ssh_dir).scan(hostname, port)

    def known_hosts_add(self, lines: list[str], profile: str | None = None) -> int:
        with self._mutating("knownhosts"):
            return KnownHostsService(self.platform, self.paths.ssh_dir).add(lines, profile)

    USER_STORE = "(user)"   # report label for the top-level ~/.ssh/known_hosts

    def init_known_hosts(self, *, profile: str | None = None, all_profiles: bool = False,
                         user: bool = False, force: bool = False) -> KnownHostsInitReport:
        """Initialize known_hosts. Ensures each target store's file exists (perms),
        then pins its reachable hosts (trust-on-first-use; fingerprints are reported
        for review). Skips already-trusted hosts unless ``force``, and unreachable/
        VPN-gated hosts (run again, or `knownhosts pin`, later).

        Scope (combinable): one ``profile`` or ``all_profiles`` (the per-profile
        stores ``~/.ssh/profiles/<p>/known_hosts`` that managed aliases use), and/or
        ``user`` (the conventional per-user ``~/.ssh/known_hosts``, consulted for any
        ad-hoc ssh/git connection that doesn't match a managed profile alias). Per-
        profile trust stays isolated; the user store aggregates every host once."""
        manifest = self.manifest()
        targets = self.known_hosts_targets()
        if all_profiles:
            profs = sorted({t[0] for t in targets})
        elif profile:
            if profile not in manifest.profiles:
                raise SshManagerError(f"unknown profile: {profile!r}")
            profs = [profile]
        else:
            profs = []
        if not profs and not user:
            raise SshManagerError("give a PROFILE, --all, or --user")
        report = KnownHostsInitReport(profiles=profs + ([self.USER_STORE] if user else []))
        khs = KnownHostsService(self.platform, self.paths.ssh_dir)
        with self._mutating("knownhosts_init"):
            for prof in profs:
                if khs.ensure(prof):
                    report.created.append(f"profiles/{prof}/known_hosts")
            for prof, alias, hostname, port in targets:
                if prof in profs:
                    report.results.append(
                        self._init_one_host(khs, prof, alias, hostname, port, force))
            if user:
                if khs.ensure(None):
                    report.created.append("known_hosts")
                seen: set[tuple[str, int]] = set()
                for _prof, alias, hostname, port in targets:   # one entry per host:port
                    if (hostname, port) in seen:
                        continue
                    seen.add((hostname, port))
                    report.results.append(
                        self._init_one_host(khs, None, alias, hostname, port, force))
        pinned = sum(1 for r in report.results if r.status == "pinned")
        log.audit(self.paths.audit_log, "knownhosts.init",
                  profiles=len(profs), user=user, pinned=pinned)
        return report

    def _init_one_host(self, khs: KnownHostsService, profile: str | None, alias: str,
                       hostname: str, port: int, force: bool) -> HostPinResult:
        label = profile if profile is not None else self.USER_STORE
        kh = khs.path_for(profile)
        token = hostname if port == 22 else f"[{hostname}]:{port}"
        if not force and _host_in_known_hosts(kh, token):
            return HostPinResult(label, alias, hostname, port, "already-trusted")
        if not net.tcp_reachable(hostname, port, timeout=4):
            return HostPinResult(label, alias, hostname, port, "unreachable")
        scanned = khs.scan(hostname, port)
        if not scanned:
            return HostPinResult(label, alias, hostname, port, "no-keys")
        khs.add([sk.line for sk in scanned], profile)
        return HostPinResult(label, alias, hostname, port, "pinned",
                             [f"{sk.keytype} {sk.fingerprint}" for sk in scanned])

    # manifest editing: profile / host CRUD
    def profile_add(self, name: str, *, key_scope: str = "per_service",
                    key_name: str | None = None) -> None:
        ManifestEditor(self.platform, self.paths).add_profile(
            name, key_scope=key_scope, key_name=key_name)

    def profile_edit(self, name: str, *, key_scope: str | None = None,
                     key_name: str | None = None) -> None:
        ManifestEditor(self.platform, self.paths).edit_profile(
            name, key_scope=key_scope, key_name=key_name)

    def profile_delete(self, name: str, *, revoke: bool) -> DeleteResult:
        return ManifestEditor(self.platform, self.paths).delete_profile(name, revoke=revoke)

    def host_add(self, profile: str, alias: str, *, hostname: str, user: str,
                 port: int = 22, provider: str | None = None,
                 token_env: str | None = None, key_name: str | None = None,
                 tags: list[str] | None = None) -> None:
        ManifestEditor(self.platform, self.paths).add_host(
            profile, alias, hostname=hostname, user=user, port=port,
            provider=provider, token_env=token_env, key_name=key_name, tags=tags)

    def host_edit(self, profile: str, alias: str, *, hostname: str | None = None,
                  user: str | None = None, port: int | None = None,
                  provider: str | None = None, token_env: str | None = None,
                  key_name: str | None = None) -> None:
        ManifestEditor(self.platform, self.paths).edit_host(
            profile, alias, hostname=hostname, user=user, port=port,
            provider=provider, token_env=token_env, key_name=key_name)

    def host_delete(self, profile: str, alias: str, *, revoke: bool) -> DeleteResult:
        return ManifestEditor(self.platform, self.paths).delete_host(
            profile, alias, revoke=revoke)

    # rotation
    def rotate(self, key_name: str, *, allow_unverified: bool = False,
               passphrase: str = "") -> RotateReport:
        with self._mutating("rotate"):
            manifest, inventory = self.manifest(), self.inventory()
            report = Rotator(self.platform, self.paths, manifest, inventory).rotate(
                key_name, allow_unverified=allow_unverified, passphrase=passphrase
            )
            if report.committed:
                inventory.save(self.paths.inventory)
            return report

    def rollback(self, key_name: str) -> RotateReport:
        with self._mutating("rollback"):
            manifest, inventory = self.manifest(), self.inventory()
            report = Rotator(self.platform, self.paths, manifest, inventory).rollback(
                key_name
            )
            inventory.save(self.paths.inventory)
            return report

    # deploy
    def deploy(self, key_name: str, target: str | None = None) -> DeployReport:
        """Install a key's public half on its target(s) + record it. Mutates
        inventory state (under lock), not ~/.ssh - so no snapshot needed."""
        with advisory_lock(self.paths.lock_file):
            manifest, inventory = self.manifest(), self.inventory()
            report = Deployer(self.platform, self.paths, manifest, inventory).deploy(
                key_name, target
            )
            inventory.save(self.paths.inventory)
            return report

    # read views (list / view) - return data; rendering lives in ssh_manager.render
    def _query(self) -> Query:
        return Query(self.manifest(), self.inventory(), self.paths.ssh_dir, self.paths.providers)

    def list_groups(self, *, profile: str | None = None, provider: str | None = None,
                    type_: str | None = None, tag: str | None = None) -> list[ProfileGroup]:
        return self._query().groups(profile=profile, provider=provider, type_=type_, tag=tag)

    def view_detail(self, selector: str) -> ProfileSummary | HostDetail:
        return self._query().detail(selector)

    # break-glass recovery (the lockout escape hatch,)
    def recovery_script(self, key_name: str | None = None) -> str:
        """A self-contained shell script to paste into a provider's web/recovery
        console when you're locked out. With a key name it emits a tailored
        snippet that re-adds *that* key to authorized_keys; without one it emits
        the full interactive fixkeys recovery tool."""
        if key_name is None:
            try:
                return _read_data("fixkeys.sh")
            except (FileNotFoundError, OSError) as exc:
                raise SshManagerError(
                    "recovery tool (fixkeys.sh) is not shipped in this build; "
                    "use `sshmgr recover <key>` for a per-key snippet instead"
                ) from exc
        pub = None
        for rk in self.manifest().iter_resolved():
            if rk.key_name == key_name:
                pub = self.paths.ssh_dir / "profiles" / rk.profile / f"{key_name}.pub"
                break
        if pub is None or not pub.exists():
            raise SshManagerError(
                f"public key not found for {key_name!r} - run `sshmgr reconcile` first")
        pubtext = pub.read_text(encoding="utf-8").strip()
        if not is_valid_public_key(pubtext):
            raise SshManagerError(f"{key_name}: {pub} is not a valid public key")
        return _recovery_snippet(key_name, pubtext)

    def config_views_for_keys(self, key_names: list[str]) -> list[HostDetail]:
        """The resolved SSH config (HostDetail) for each host using the given keys
        - shown after keygen/reconcile so you see exactly how each new key is
        wired (IdentityFile, UserKnownHostsFile, provider) and how to deploy it."""
        manifest = self.manifest()
        q = self._query()
        wanted = set(key_names)
        seen: set[str] = set()
        views: list[HostDetail] = []
        for rk in manifest.iter_resolved():
            if rk.key_name in wanted and rk.host.alias not in seen:
                seen.add(rk.host.alias)
                detail = q.detail(rk.host.alias)
                if isinstance(detail, HostDetail):
                    views.append(detail)
        return views

    def import_ssh(self, config_path: Path, *, dry_run: bool = False,
                   force: bool = False) -> ImportResult:
        if dry_run:
            return Importer(self.platform, self.paths).run(config_path, dry_run=True)
        with self._mutating("import"):
            # import REPLACES the manifest + inventory wholesale (it doesn't merge),
            # and those live in the per-user home - outside the ~/.ssh snapshot. Refuse to
            # clobber a non-empty manifest unless --force, and back both up first.
            existing = None
            with contextlib.suppress(ManifestError):
                existing = self.manifest()
            if existing and existing.profiles and not force:
                raise SshManagerError(
                    "a non-empty manifest already exists - importing replaces it "
                    "(it does not merge). Re-run with --force; the current manifest + "
                    "inventory are backed up to <home>/.state/ first.")
            if existing and existing.profiles:
                self._backup_import_targets()
            return Importer(self.platform, self.paths).run(config_path, dry_run=False)

    def _backup_import_targets(self) -> None:
        backup = self.paths.state_dir / f"import-backup-{datetime.now():%Y%m%d-%H%M%S}"
        for src in (self.paths.manifest, self.paths.inventory):
            if src.exists():
                fs.ensure_dir(backup, SECRET_DIR_MODE)
                shutil.copy2(src, backup / src.name)

    # snapshots (local reversible backup of ~/.ssh)
    def list_snapshots(self) -> list[Path]:
        return fs.list_snapshots(self.paths.snapshots_dir)

    def restore_snapshot(self, snapshot_id: str | None = None) -> Path:
        """Restore ~/.ssh from a snapshot (latest if unspecified). Snapshots the
        current tree first so the restore is itself reversible, then re-applies
        perms on managed paths."""
        snaps = self.list_snapshots()
        if not snaps:
            raise SshManagerError("no snapshots to restore from")
        if snapshot_id is None:
            chosen = snaps[-1]
        else:
            matches = [s for s in snaps if snapshot_id in s.name]
            if not matches:
                raise SshManagerError(f"no snapshot matching {snapshot_id!r}")
            chosen = matches[-1]
        # The mutation guard snapshots ~/.ssh first, which can prune the oldest
        # snapshot - possibly `chosen` itself. Restore from a copy pruning can't reach.
        with tempfile.TemporaryDirectory() as tmp:
            safe = Path(tmp) / chosen.name
            shutil.copy2(chosen, safe)
            with self._mutating("restore_snapshot"):
                fs.restore_snapshot(safe, self.paths.ssh_dir)
                for path, mode in perms.iter_managed_paths(self.paths.ssh_dir):
                    self.platform.set_perms(path, mode)
        return chosen

    def prune_snapshots(self, keep: int = SNAPSHOT_RETAIN) -> int:
        snaps = self.list_snapshots()
        remove = snaps[:-keep] if keep > 0 else snaps
        for s in remove:
            s.unlink(missing_ok=True)
        return len(remove)

    def diff(self) -> str:
        manifest = self.manifest()
        cfg = ConfigService(self.platform, self.paths, manifest).check()
        lines = ["=== config ===", cfg.format(), "", "=== keys ==="]
        missing, present = [], 0
        for rk in manifest.iter_resolved():
            priv = self.paths.ssh_dir / "profiles" / rk.profile / rk.key_name
            if priv.exists():
                present += 1
            else:
                missing.append(f"  MINT  {rk.key_name} (manifest wants it; not on disk)")
        if missing:
            lines.extend(missing)
        lines.append(f"  {present} key(s) already present")
        return "\n".join(lines)

    def export_providers(self, *, force: bool = False) -> Path:
        """Write the shipped default provider catalog to ``<home>/providers.json`` so
        the user can customize it. Refuses to overwrite an existing file unless
        ``force``. The tool works without this file (the shipped catalog is the
        default); this just materializes an editable copy."""
        dest = self.paths.providers
        if dest.exists() and not force:
            raise SshManagerError(f"{dest} already exists - use --force to overwrite it")
        try:
            text = _read_data("providers.json")
        except (FileNotFoundError, OSError) as exc:
            raise SshManagerError("no shipped provider catalog found in this build") from exc
        with advisory_lock(self.paths.lock_file):
            fs.ensure_dir(self.paths.config_dir, SECRET_DIR_MODE)
            fs.write_text_atomic(dest, text, 0o644)
        log.audit(self.paths.audit_log, "providers.export", path=str(dest))
        return dest

    def providers_source(self) -> str:
        """Where the active provider catalog comes from: the user's file or the
        shipped default."""
        return "user file" if self.paths.providers.exists() else "shipped default"

    def list_providers(self) -> list[ProviderInfo]:
        """Every configured provider + whether its token env var is set now."""
        from ..providers.registry import all_specs
        out: list[ProviderInfo] = []
        for name, spec in sorted(all_specs(self.paths.providers).items()):
            present = bool(spec.token_env and os.environ.get(spec.token_env))
            out.append(ProviderInfo(name, spec.kind, spec.category, spec.token_env, present))
        return out

    def network_status(self, selector: str | None = None) -> list[HostNet]:
        """Reachability + VPN status for each host in the manifest (the network
        indicator). ``selector`` filters by alias, profile, or key name. Uses a
        fast TCP probe; hosts marked ``requires_vpn`` get a VPN-aware message."""
        out: list[HostNet] = []
        for rk in self.manifest().iter_resolved():
            h = rk.host
            if selector and selector not in (h.alias, rk.profile, rk.key_name):
                continue
            st = net.check(h.hostname, h.port, requires_vpn=h.requires_vpn,
                           vpn_name=h.vpn_name, vpn_url=h.vpn_url)
            out.append(HostNet(rk.profile, h.alias, st))
        return out

    def validate_keys(self, selector: str | None = None) -> list[KeyCheck]:
        """Validate managed keypairs: each private + public key parses, the pair
        matches (same fingerprint - read from the public half, so no passphrase is
        needed even for encrypted keys), and perms are correct. ``selector`` filters
        by key name or profile; omit it to validate every managed key."""
        keystore = KeyStore(self.platform)
        resolved = list(self.manifest().iter_resolved())
        if selector and not any(selector in (rk.key_name, rk.profile) for rk in resolved):
            raise SshManagerError(f"unknown key or profile: {selector!r}")
        seen: set[str] = set()
        checks: list[KeyCheck] = []
        for rk in resolved:
            if rk.key_name in seen:
                continue
            if selector and selector not in (rk.key_name, rk.profile):
                continue
            seen.add(rk.key_name)
            priv = self.paths.ssh_dir / "profiles" / rk.profile / rk.key_name
            checks.append(self._validate_one(keystore, rk.profile, rk.key_name, priv))
        return checks

    def _validate_one(self, keystore: KeyStore, profile: str, key_name: str,
                      priv: Path) -> KeyCheck:
        pub = priv.with_suffix(".pub")
        issues: list[str] = []
        notes: list[str] = []
        fp: str | None = None
        pub_text = ""
        if not priv.exists():
            issues.append("private key missing")
        elif not self.platform.perms_ok(priv, perms.PRIVATE_KEY_MODE):
            issues.append(f"private key perms not {oct(perms.PRIVATE_KEY_MODE)[2:]}")
        if not pub.exists():
            issues.append("public key (.pub) missing")
        else:
            pub_text = pub.read_text(encoding="utf-8").strip()
            if not is_valid_public_key(pub_text):
                issues.append("public key is malformed")
            else:
                with contextlib.suppress(SshManagerError):
                    fp = keystore.fingerprint(pub)
            if not self.platform.perms_ok(pub, perms.PUBLIC_KEY_MODE):
                issues.append(f"public key perms not {oct(perms.PUBLIC_KEY_MODE)[2:]}")
        # Real pair check: derive the public key from the private material.
        if priv.exists():
            derived, encrypted = keystore.public_from_private(priv)
            if derived is not None:
                if pub_text and key_body(derived) != key_body(pub_text):
                    issues.append("public key does NOT match the private key")
            elif encrypted:
                notes.append("encrypted - pair not verified without passphrase")
            else:
                issues.append("private key unreadable / not a valid key")
        return KeyCheck(key_name=key_name, profile=profile, fingerprint=fp,
                        ok=not issues, issues=issues, notes=notes)

    def doctor(self) -> DoctorReport:
        rep = DoctorReport(preflight=check(self.platform))
        rep.home = self.paths.config_dir
        rep.ssh_dir = self.paths.ssh_dir
        rep.providers_source = self.providers_source()
        legacy = self._first_legacy_home(self.paths.config_dir)
        if legacy is not None and self.paths.config_dir.exists():
            rep.stranded_legacy_home = legacy
        ssh = self.paths.ssh_dir
        rep.perm_issues = self._perm_issues(ssh)
        rep.agent_status = self._agent_status()
        # per-profile trust stores (or the top-level fallback)
        rep.known_hosts = (ssh / "known_hosts").exists() or any(
            (ssh / "profiles").glob("*/known_hosts")
        )
        rep.old_keys = self._old_key_counts(ssh)
        try:
            manifest = self.manifest()
            rep.config_in_sync = ConfigService(
                self.platform, self.paths, manifest).check().in_sync
            rep.orphan_keys = self._orphan_keys(ssh, manifest)
            rep.duplicate_keys = self._duplicate_keys(ssh)
            rep.unpinned_hosts = self._unpinned_host_keys(ssh, manifest)
            rep.alias_collisions = self._alias_collisions(manifest)
        except ManifestError:
            rep.config_in_sync = True  # no manifest yet -> nothing to drift from
        return rep

    @staticmethod
    def _alias_collisions(manifest: Manifest) -> list[str]:
        """Aliases used by hosts in more than one profile. Since every profile's
        config is pulled in by `Include profiles/*/config`, ssh applies the FIRST
        matching `Host` block - so a duplicate alias silently routes to the wrong
        host/key. Report each colliding alias with the profiles that define it."""
        where: dict[str, list[str]] = {}
        for pname, profile in manifest.profiles.items():
            for host in profile.hosts:
                where.setdefault(host.alias, []).append(pname)
        return [f"{alias} (profiles: {', '.join(sorted(set(profs)))})"
                for alias, profs in sorted(where.items()) if len(set(profs)) > 1]

    def _unpinned_host_keys(self, ssh: Path, manifest: Manifest) -> list[str]:
        """Manifest hosts whose per-profile known_hosts has no entry for them.

        With per-profile UserKnownHostsFile + OpenSSH's default
        StrictHostKeyChecking=ask, such a host fails non-interactive ssh/git with
        'Host key verification failed' - so doctor surfaces it with the remedy.
        """
        out: list[str] = []
        seen: set[tuple[str, str, int]] = set()
        for rk in manifest.iter_resolved():
            h = rk.host
            key = (rk.profile, h.hostname, h.port)
            if key in seen:
                continue
            seen.add(key)
            kh = ssh / "profiles" / rk.profile / "known_hosts"
            token = h.hostname if h.port == 22 else f"[{h.hostname}]:{h.port}"
            if not _host_in_known_hosts(kh, token):
                out.append(f"{h.alias} ({h.hostname})")
        return out

    def _orphan_keys(self, ssh: Path, manifest: Manifest) -> list[str]:
        """Private-key files directly under profiles/<p>/ whose key_name isn't in
        the manifest (e.g. left behind after a host/profile delete)."""
        referenced = {rk.key_name for rk in manifest.iter_resolved()}
        prof_dir = ssh / "profiles"
        if not prof_dir.is_dir():
            return []
        orphans: list[str] = []
        for priv in sorted(prof_dir.glob("*/*")):
            # Only real private-key files: not dirs, not .pub, not the managed
            # `config`, not hidden OS cruft (.DS_Store) - and only if it has a
            # public half (a keypair) yet isn't referenced by the manifest.
            if (priv.is_dir() or priv.name.endswith(".pub")
                    or priv.name == "config" or priv.name.startswith(".")):
                continue
            if not priv.with_suffix(".pub").exists():
                continue
            if priv.name not in referenced:
                orphans.append(str(priv.relative_to(ssh)))
        return orphans

    def _duplicate_keys(self, ssh: Path) -> list[str]:
        """Active keys sharing a fingerprint (key reuse widens blast radius, §1)."""
        prof_dir = ssh / "profiles"
        if not prof_dir.is_dir() or not proc.has("ssh-keygen"):
            return []
        keystore = KeyStore(self.platform)
        by_fp: dict[str, list[str]] = {}
        for pub in sorted(prof_dir.glob("*/*.pub")):
            with contextlib.suppress(Exception):
                by_fp.setdefault(keystore.fingerprint(pub), []).append(pub.stem)
        dups: list[str] = []
        for names in by_fp.values():
            if len(names) > 1:
                dups.append(" = ".join(sorted(names)))
        return dups

    # doctor helpers
    def _perm_issues(self, ssh: Path) -> list[str]:
        """Check perms over the SAME managed-path enumeration reconcile fixes, so
        the checker and the fixer can never disagree (and neither touches files a
        user keeps in ~/.ssh)."""
        issues: list[str] = []
        for path, want in perms.iter_managed_paths(ssh):
            if not self.platform.perms_ok(path, want):
                have = path.stat().st_mode & 0o777
                issues.append(f"{path}: {have:o} (want {want:o})")
        return issues

    def _agent_status(self) -> str:
        if not proc.has("ssh-add"):
            return "ssh-add not found"
        r = proc.run(["ssh-add", "-l"])
        if r.returncode == 0:
            return f"running, {len(r.stdout.strip().splitlines())} key(s) loaded"
        if r.returncode == 1:
            return "running, no identities loaded"
        return "not running"

    def _old_key_counts(self, ssh: Path) -> dict[str, int]:
        """Archived predecessors per KEY NAME (invariant: ≤1 each). Counting by
        key name - not per profile dir - so a profile that has rotated several
        distinct keys isn't falsely flagged."""
        counts: dict[str, int] = {}
        prof_dir = ssh / "profiles"
        if not prof_dir.is_dir():
            return counts
        for old in prof_dir.glob("*/old"):
            if old.is_dir():
                for p in old.iterdir():
                    if p.name.endswith(".pub") or p.is_dir():
                        continue
                    counts[p.name] = counts.get(p.name, 0) + 1
        return counts


def _auto_pin_disabled() -> bool:
    """SSH_MANAGER_AUTO_PIN set to a falsy string disables auto-pinning (0/false/no/off)."""
    val = (os.environ.get("SSH_MANAGER_AUTO_PIN") or "").strip().lower()
    return val in {"0", "false", "no", "off"}


def _move_dir(src: Path, dst: Path) -> None:
    """Move a directory: atomic same-filesystem rename, falling back to a copy-move
    across filesystems (the caller guarantees ``dst`` is absent, so no nesting)."""
    try:
        os.rename(src, dst)
    except OSError:
        shutil.move(str(src), str(dst))


def _host_in_known_hosts(path: Path, token: str) -> bool:
    """True if ``token`` (a hostname or ``[host]:port``) is a pinned host in the
    known_hosts file. Matches ssh-keyscan's plaintext output (the first field may
    be a comma-list of host/IP); hashed entries aren't produced by `knownhosts pin`."""
    if not path.is_file():
        return False                         # absent, or a dir/symlink-to-dir, etc.
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        # An @cert-authority / @revoked marker shifts the host to the 2nd field.
        if fields and fields[0].startswith("@") and len(fields) > 1:
            host_field = fields[1]
        else:
            host_field = fields[0]
        if token in host_field.split(","):
            return True
    return False


def _read_data(name: str) -> str:
    from importlib.resources import files
    return (files("ssh_manager") / "data" / name).read_text(encoding="utf-8")


def _recovery_snippet(key_name: str, pubkey: str) -> str:
    # Compute the base64 body here (robust) rather than awk '$2' in the snippet,
    # which breaks for option-prefixed key lines. Escape both values for a POSIX
    # single-quoted literal so an arbitrary key comment can't break/inject the script.
    body = key_body(pubkey)
    safe_key = pubkey.replace("'", "'\\''")
    safe_body = body.replace("'", "'\\''")
    return f"""\
#!/bin/sh
# ssh-manager recovery: paste into a locked-out server's console to re-add this key.
# key: {key_name}
set -e
KEY='{safe_key}'
BODY='{safe_body}'
AK="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$AK"
cp "$AK" "$AK.ssh-manager.bak" 2>/dev/null || true
grep -qF "$BODY" "$AK" || printf '%s\\n' "$KEY" >> "$AK"
chmod 600 "$AK"
echo "ssh-manager: key in place. Test SSH from another terminal before closing this console."
"""


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


_DEFAULT_ENV = """\
# ssh-manager environment (gitignored). Keep this file at mode 0600.
SSH_MANAGER_HOME=
SSH_MANAGER_AGE_RECIPIENT=
SSH_MANAGER_AGE_IDENTITY_FILE=
SSH_MANAGER_SNAPSHOT_RETAIN=10
GH_TOKEN=
GH_TOKEN_SIMTABI=
"""
