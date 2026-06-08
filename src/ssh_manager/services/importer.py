"""Onboard an existing ~/.ssh into the manifest + inventory.

`import` parses an existing ssh config (following ``Include`` directives) into
manifest profiles + hosts, and fingerprints any private keys it can find into the
inventory - so you never hand-write JSON. Profile assignment derives from an
``IdentityFile`` path under ``profiles/<profile>/`` when present, else ``imported``.
"""
from __future__ import annotations

import contextlib
import glob
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..core.inventory import Inventory, KeyRecord
from ..core.key import derive_key_name
from ..core.manifest import (
    _DANGEROUS_OPTIONS,
    DEFAULT_GLOBAL_OPTIONS,
    Defaults,
    Host,
    Manifest,
    Profile,
)
from ..platforms.base import Platform
from ..util import perms
from ..util.errors import ManifestError
from ..util.paths import Paths
from .keystore import KeyStore


@dataclass
class ParsedHost:
    alias: str
    hostname: str = ""
    user: str = ""
    port: int = 22
    identity_file: str | None = None
    profile: str = "imported"
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class ImportResult:
    profiles: dict[str, int] = field(default_factory=dict)   # profile -> host count
    keys_found: int = 0
    adopted: int = 0          # existing keys copied into the profiles/ layout
    dry_run: bool = False

    def format(self) -> str:
        head = "import (dry-run):" if self.dry_run else "import:"
        lines = [head]
        for p, n in sorted(self.profiles.items()):
            lines.append(f"  profile {p}: {n} host(s)")
        lines.append(f"  keys fingerprinted into inventory: {self.keys_found}")
        if self.adopted:
            lines.append(f"  keys adopted into profiles/ layout: {self.adopted}")
        return "\n".join(lines)


_SIMPLE_KEYS = {"hostname", "user", "port", "identityfile"}
_PROVIDER_BY_HOST = {
    "github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket",
}


def _infer_provider(hostname: str) -> str | None:
    return _PROVIDER_BY_HOST.get(hostname.lower())


def parse_ssh_config(text: str, *, base_dir: Path | None = None,
                     _seen: set[Path] | None = None) -> list[ParsedHost]:
    """Parse ssh config text into hosts, following relative ``Include`` files.

    Pure over its inputs (``base_dir`` only used to resolve includes); ``Host *``
    and other wildcard/global blocks are skipped - they carry no concrete host. A
    ``Host`` line with several patterns applies its options to *all* of them (as ssh
    does); a ``Match`` line ends the current block (ssh-manager doesn't model Match).
    """
    hosts: list[ParsedHost] = []
    current: list[ParsedHost] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        keyword = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if keyword == "host":
            current = []
            for alias in value.split():
                if any(c in alias for c in "*?!"):
                    continue
                ph = ParsedHost(alias=alias)
                current.append(ph)
                hosts.append(ph)
        elif keyword == "match":
            current = []                 # Match block: unmodeled, ends the host block
        elif keyword == "include" and base_dir is not None:
            hosts.extend(_parse_includes(value, base_dir, _seen or set()))
            current = []
        else:
            for ph in current:
                _apply_option(ph, keyword, value)
    return hosts


def _apply_option(host: ParsedHost, keyword: str, value: str) -> None:
    if keyword == "hostname":
        host.hostname = value
    elif keyword == "user":
        host.user = value
    elif keyword == "port":
        with contextlib.suppress(ValueError):
            host.port = int(value)
    elif keyword == "identityfile":
        host.identity_file = value
        host.profile = _profile_from_identity(value)
    elif keyword in _DANGEROUS_OPTIONS:
        # Code/config-executing directives (ProxyCommand, Match, Include, ...) are
        # dropped on import rather than carried into the manifest (where validation
        # would reject them and abort the whole import).
        return
    elif keyword not in _SIMPLE_KEYS:
        host.extra[keyword] = value


def _profile_from_identity(identity_file: str) -> str:
    parts = Path(identity_file).parts
    if "profiles" in parts:
        i = parts.index("profiles")
        if i + 1 < len(parts):
            return parts[i + 1]
    return "imported"


def _parse_includes(pattern: str, base_dir: Path, seen: set[Path]) -> list[ParsedHost]:
    hosts: list[ParsedHost] = []
    for token in pattern.split():
        expanded = os.path.expanduser(token)
        full = expanded if os.path.isabs(expanded) else str(base_dir / expanded)
        for match in sorted(glob.glob(full)):
            mpath = Path(match).resolve()
            if mpath in seen or not mpath.is_file():
                continue
            seen.add(mpath)
            hosts.extend(parse_ssh_config(
                mpath.read_text(encoding="utf-8"), base_dir=base_dir, _seen=seen
            ))
    return hosts


@dataclass
class _Resolution:
    """How one parsed host maps onto the canonical layout."""

    key_name: str
    adopt_from: Path | None = None   # source key to copy into profiles/<p>/ (if any)
    probe: Path | None = None        # existing key to fingerprint (source-side)


class Importer:
    def __init__(self, platform: Platform, paths: Paths) -> None:
        self._platform = platform
        self._paths = paths
        self._keystore = KeyStore(platform)

    def run(self, config_path: Path, *, dry_run: bool = False) -> ImportResult:
        config_path = config_path.expanduser()
        if not config_path.is_file():
            raise ManifestError(f"no ssh config file to import: {config_path}")
        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ManifestError(f"cannot read {config_path}: {exc}") from exc
        parsed = parse_ssh_config(text, base_dir=config_path.parent)
        opts = dict(DEFAULT_GLOBAL_OPTIONS)
        if not self._platform.emits_use_keychain:
            opts.pop("UseKeychain", None)

        # Pass 1: build the full profile map, then the manifest (pydantic copies
        # the dict on construct, so it must be complete before we build it).
        profiles: dict[str, Profile] = {}
        resolved: list[tuple[ParsedHost, _Resolution]] = []
        seen: set[tuple[str, str]] = set()
        for h in parsed:
            if (h.profile, h.alias) in seen:
                continue                 # duplicate Host block in the source - first wins
            seen.add((h.profile, h.alias))
            res = self._resolve_key(h)
            resolved.append((h, res))
            host = Host(
                alias=h.alias, hostname=h.hostname or h.alias,
                user=h.user or os.environ.get("USER", "git"),
                port=h.port, key_name=res.key_name,
                provider=_infer_provider(h.hostname or h.alias),
                raw_options=dict(h.extra),   # carry unmodeled options (ProxyJump, ...)
            )
            profiles.setdefault(h.profile, Profile()).hosts.append(host)
        manifest = Manifest(defaults=Defaults(global_options=opts), profiles=profiles)

        # Pass 2: adopt keys into the profiles/ layout + fingerprint into inventory.
        # The recorded path is the canonical IdentityFile the renderer will emit,
        # so import + reconcile never disagree (no phantom-key minting).
        inventory = Inventory()
        adopted = 0
        for h, res in resolved:
            ident = manifest.identity_file(h.profile, res.key_name)
            if (not dry_run and res.adopt_from is not None
                    and self._adopt_key(res.adopt_from, h.profile, res.key_name)):
                adopted += 1
            if res.probe is not None:
                fp = self._safe_fingerprint(res.probe)
                if fp:
                    inventory.record(fp, KeyRecord(profile=h.profile, path=ident))

        result = ImportResult(dry_run=dry_run, keys_found=len(inventory.keys))
        result.adopted = adopted
        for h in parsed:
            result.profiles[h.profile] = result.profiles.get(h.profile, 0) + 1
        if not dry_run:
            manifest.save(self._paths.manifest)
            inventory.save(self._paths.inventory)
        return result

    def _resolve_key(self, h: ParsedHost) -> _Resolution:
        if not h.identity_file:
            # No key on disk to adopt; reconcile will mint a canonical one.
            return _Resolution(derive_key_name(h.profile, h.alias))
        real = Path(os.path.expanduser(h.identity_file))
        pub = real.with_suffix(".pub")
        probe: Path | None = pub if pub.exists() else (real if real.exists() else None)
        if self._under_profile(real, h.profile):
            # Already canonical - keep its filename; nothing to adopt.
            return _Resolution(real.name, adopt_from=None, probe=probe)
        # Non-canonical location (e.g. ~/.ssh/id_ed25519): adopt it into the
        # profiles/ layout under a canonical name so the manifest is faithful.
        canonical = derive_key_name(h.profile, h.alias)
        return _Resolution(
            canonical, adopt_from=real if real.exists() else None, probe=probe
        )

    @staticmethod
    def _under_profile(real: Path, profile: str) -> bool:
        parts = real.parts
        return "profiles" in parts and parts[parts.index("profiles") + 1 :][:1] == (profile,)

    def _adopt_key(self, src_priv: Path, profile: str, key_name: str) -> bool:
        """Copy an existing keypair into profiles/<profile>/<key_name> (perms set).
        Non-destructive: skips if the destination already exists."""
        dst_priv = self._paths.ssh_dir / "profiles" / profile / key_name
        if dst_priv.exists() or not src_priv.exists():
            return False
        dst_priv.parent.mkdir(parents=True, exist_ok=True)
        self._platform.set_perms(dst_priv.parent, perms.DIR_MODE)
        shutil.copy2(src_priv, dst_priv)
        self._platform.set_perms(dst_priv, perms.PRIVATE_KEY_MODE)
        src_pub, dst_pub = src_priv.with_suffix(".pub"), dst_priv.with_suffix(".pub")
        if src_pub.exists():
            shutil.copy2(src_pub, dst_pub)
            self._platform.set_perms(dst_pub, perms.PUBLIC_KEY_MODE)
        return True

    def _safe_fingerprint(self, probe: Path) -> str | None:
        try:
            return self._keystore.fingerprint(probe)
        except Exception:
            return None
