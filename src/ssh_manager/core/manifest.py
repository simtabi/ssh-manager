"""Manifest domain models. Validated with pydantic v2.

The manifest is the single source of truth (invariant 1). These models load/save
through the atomic JSON store and expose the per-host key resolution the renderer
and reconciler depend on (``per_service`` default, ``shared`` opt-in).
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..util import jsonstore
from ..util.errors import ManifestError
from .key import derive_key_name

SCHEMA_VERSION = 1
SSH_TOKEN = "~/.ssh"  # IdentityFile paths in rendered config use the ~ form

# --- input hardening -------------------------------------------------------
# The manifest is rendered verbatim into ~/.ssh/config and its names become
# filesystem paths, so untrusted values (a hand-edited manifest, an imported
# foreign ssh config) must not inject config directives, escape the key tree, or
# smuggle leading-dash arguments into ssh.
import re as _re  # noqa: E402

_CONTROL = _re.compile(r"[\x00-\x1f\x7f]")          # newline/tab/NUL/other control

# ssh options that run a command, load a shared object, or pull in further config
# - never allowed in raw_options / global_options. ProxyJump (a host, not a
# command) stays allowed. This is a denylist of the known code/config-execution
# directives; values are additionally guarded for control chars + leading dash.
_DANGEROUS_OPTIONS = frozenset({
    "proxycommand", "localcommand", "permitlocalcommand", "remotecommand",
    "match", "include", "knownhostscommand", "pkcs11provider", "securitykeyprovider",
})


def _reject_control(field: str, value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError(f"{field} contains a control character or newline")
    return value


def _safe_segment(field: str, value: str) -> str:
    """A safe single filesystem path component + ssh token: no traversal, no
    separators, no leading dash, no control chars, no whitespace (would split into
    two config tokens / two key paths), and no glob metacharacters ``*?`` (an
    alias of ``*`` would render a wildcard ``Host`` block that overrides others)."""
    _reject_control(field, value)
    if (value in ("", ".", "..") or "/" in value or "\\" in value
            or value.startswith("-") or any(c.isspace() for c in value)
            or any(c in value for c in "*?")):
        raise ValueError(
            f"{field}={value!r} is not a safe name "
            "(no empty/'.'/'..'/'/'/'\\\\'/leading '-'/whitespace/'*'/'?')")
    return value


def _safe_value(field: str, value: str) -> str:
    """A non-path string still rendered into config / passed to ssh: no control
    chars, no leading dash (would be parsed as an ssh option), no whitespace (a
    hostname/user with a space would split into extra config tokens)."""
    _reject_control(field, value)
    if value.startswith("-"):
        raise ValueError(f"{field}={value!r} must not start with '-'")
    if any(c.isspace() for c in value):
        raise ValueError(f"{field}={value!r} must not contain whitespace")
    return value


_KEY_SCOPES = frozenset({"per_service", "shared"})


def _check_key_scope(value: str) -> str:
    if value not in _KEY_SCOPES:
        raise ValueError(f"key_scope must be one of {sorted(_KEY_SCOPES)} (got {value!r})")
    return value


def _check_options(field: str, opts: dict[str, str]) -> dict[str, str]:
    for k, v in opts.items():
        _reject_control(f"{field} key {k!r}", k)
        _reject_control(f"{field}[{k}]", v)
        if k.lower() in _DANGEROUS_OPTIONS:
            raise ValueError(f"{field} key {k!r} is not allowed (it can execute commands)")
    return opts

# Canonical Host* defaults. UseKeychain is dropped off macOS by the
# renderer; IgnoreUnknown must precede the option it guards.
DEFAULT_GLOBAL_OPTIONS: dict[str, str] = {
    "AddKeysToAgent": "yes",
    "IgnoreUnknown": "UseKeychain",
    "UseKeychain": "yes",
    "IdentitiesOnly": "yes",
    "ServerAliveInterval": "60",
}


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str
    hostname: str
    user: str
    port: int = 22
    provider: str | None = None          # named adapter; else generic SSH
    token_env: str | None = None         # per-host provider credential ref
    key_name: str | None = None          # None when profile key_scope == "shared"
    tags: list[str] = Field(default_factory=list)
    requires_vpn: bool = False           # host is only reachable over a VPN
    vpn_name: str | None = None          # which VPN (shown in the reachability hint)
    vpn_url: str | None = None           # where to connect that VPN (shown in the hint)
    raw_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("raw_options", mode="before")
    @classmethod
    def _stringify_raw(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: str(v) for k, v in value.items()}
        return value

    @field_validator("alias", "key_name")
    @classmethod
    def _v_segment(cls, value: str | None, info: Any) -> str | None:
        return value if value is None else _safe_segment(info.field_name, value)

    @field_validator("hostname", "user")
    @classmethod
    def _v_value(cls, value: str, info: Any) -> str:
        return _safe_value(info.field_name, value)

    @field_validator("raw_options")
    @classmethod
    def _v_raw_options(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_options("raw_options", value)


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_scope: str = "per_service"          # "per_service" | "shared"
    key_name: str | None = None          # used when key_scope == "shared"
    hosts: list[Host] = Field(default_factory=list)

    @field_validator("key_name")
    @classmethod
    def _v_key_name(cls, value: str | None) -> str | None:
        return value if value is None else _safe_segment("profile key_name", value)

    @field_validator("key_scope")
    @classmethod
    def _v_key_scope(cls, value: str) -> str:
        return _check_key_scope(value)


class ExpiryCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    debounce_hours: int = 24
    desktop_notify: bool = True


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_type: str = "ed25519"
    key_scope: str = "per_service"
    rotate_after_days: int = 365
    warn_before_days: list[int] = Field(default_factory=lambda: [30, 14, 7, 1])
    expiry_check: ExpiryCheck = Field(default_factory=ExpiryCheck)
    global_options: dict[str, str] = Field(default_factory=dict)

    @field_validator("global_options", mode="before")
    @classmethod
    def _stringify_options(cls, value: Any) -> Any:
        """ssh option values may be numbers in JSON (e.g. ServerAliveInterval: 60);
        render needs strings, so coerce here at the edge."""
        if isinstance(value, dict):
            return {k: str(v) for k, v in value.items()}
        return value

    @field_validator("global_options")
    @classmethod
    def _v_global_options(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_options("global_options", value)

    @field_validator("key_scope")
    @classmethod
    def _v_key_scope(cls, value: str) -> str:
        return _check_key_scope(value)


class ResolvedKey(BaseModel):
    """A host paired with its resolved key name + IdentityFile path."""

    profile: str
    host: Host
    key_name: str
    identity_file: str          # e.g. ~/.ssh/profiles/work/work_unc-ed25519


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = SCHEMA_VERSION
    defaults: Defaults = Field(default_factory=Defaults)
    profiles: dict[str, Profile] = Field(default_factory=dict)

    @field_validator("profiles")
    @classmethod
    def _v_profile_names(cls, value: dict[str, Profile]) -> dict[str, Profile]:
        for name in value:                       # profile names become directory paths
            _safe_segment("profile name", name)
        return value

    @model_validator(mode="after")
    def _v_key_name_uniqueness(self) -> Manifest:
        """A key_name must belong to exactly one profile. rotate/deploy/rollback
        resolve a key_name back to its host(s) and assume they all share ONE
        profile dir; if two profiles reused a name (e.g. two ``shared`` profiles
        both named their key ``deploy``), rotating one would mint into one profile's
        dir yet deploy to the other profile's hosts - orphaning/locking them out.
        Reject that at load so the invariant the lifecycle ops rely on holds."""
        owner: dict[str, str] = {}
        for pname, profile in self.profiles.items():
            for host in profile.hosts:
                try:
                    kname = self.resolved_key_name(pname, host)
                except ManifestError:
                    # An unresolvable key (e.g. shared profile missing key_name) is
                    # reported by resolved_key_name at use-time; don't pre-empt that
                    # distinct, more specific error here.
                    continue
                prev = owner.setdefault(kname, pname)
                if prev != pname:
                    raise ManifestError(
                        f"key_name {kname!r} is used by both profile {prev!r} and "
                        f"{pname!r}; a key_name must be unique across profiles "
                        "(rename one, or namespace it per profile)")
        return self

    # Repository pattern (atomic, version-stamped)
    @classmethod
    def load(cls, path: str | Path) -> Manifest:
        path = Path(path)
        if not path.exists():
            raise ManifestError(f"manifest not found: {path} (run: sshmgr init)")
        try:
            data = jsonstore.read_json(path)
        except ValueError as exc:
            raise ManifestError(f"manifest is not valid JSON: {path}: {exc}") from exc
        except OSError as exc:
            raise ManifestError(f"manifest could not be read: {path}: {exc}") from exc
        try:
            return cls.model_validate(data)
        except Exception as exc:  # pydantic ValidationError -> our typed error
            raise ManifestError(f"manifest failed validation: {exc}") from exc

    def save(self, path: str | Path) -> None:
        jsonstore.write_json_atomic(path, self.model_dump(mode="json"))

    @classmethod
    def starter(cls, *, emit_use_keychain: bool = True) -> Manifest:
        """A minimal valid manifest for `sshmgr init` - defaults + no profiles."""
        opts = dict(DEFAULT_GLOBAL_OPTIONS)
        if not emit_use_keychain:
            opts.pop("UseKeychain", None)
        return cls(defaults=Defaults(global_options=opts), profiles={})

    # key resolution (per_service default, shared opt-in)
    def resolved_key_name(self, profile_name: str, host: Host) -> str:
        profile = self.profiles[profile_name]
        if profile.key_scope == "shared":
            if not profile.key_name:
                raise ManifestError(
                    f"profile {profile_name!r} is shared but sets no key_name"
                )
            return profile.key_name
        if host.key_name:
            return host.key_name
        algo = self.defaults.key_type
        return derive_key_name(profile_name, host.alias, algo)

    def identity_file(self, profile_name: str, key_name: str) -> str:
        return f"{SSH_TOKEN}/profiles/{profile_name}/{key_name}"

    def known_hosts_file(self, profile_name: str) -> str:
        """Per-profile host-key trust store - everything lives under the profile,
        so a host key trusted in one identity context never bleeds into another."""
        return f"{SSH_TOKEN}/profiles/{profile_name}/known_hosts"

    def iter_resolved(self) -> Iterator[ResolvedKey]:
        """Yield every host with its resolved key, skipping empty profiles."""
        for pname, profile in self.profiles.items():
            for host in profile.hosts:
                kname = self.resolved_key_name(pname, host)
                yield ResolvedKey(
                    profile=pname, host=host, key_name=kname,
                    identity_file=self.identity_file(pname, kname),
                )

    def non_empty_profiles(self) -> list[str]:
        return [name for name, p in self.profiles.items() if p.hosts]
