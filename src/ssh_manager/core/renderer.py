"""Deterministic config rendering (Jinja2).

The SINGLE renderer (invariant 3): ``config render`` (write), ``config check``
(verify), and ``reconcile`` all call :func:`render_all`, so they can never
disagree. Output carries the managed-marker header and is platform-filtered
(``UseKeychain`` only where ``platform.emits_use_keychain``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from jinja2 import Environment, PackageLoader

from .manifest import Manifest

MANAGED_HEADER = "# Managed by ssh-manager - do not edit (run: sshmgr config render)"
MANAGED_END = "# End of ssh-manager-managed block - content outside it is preserved"
# Pre-rename markers, still recognised so a config written by the old ``sshmgr``
# name is cleanly re-owned (not duplicated) on the next render.
_LEGACY_HEADERS = ("# Managed by sshmgr - do not edit (run: sshmgr config render)",)
_LEGACY_ENDS = ("# End of sshmgr-managed block - content outside it is preserved",)
_HEADERS = (MANAGED_HEADER, *_LEGACY_HEADERS)
_ENDS = (MANAGED_END, *_LEGACY_ENDS)
ROOT_CONFIG = "config"


@dataclass(frozen=True)
class RenderHost:
    """The flat view a template needs for one ``Host`` block."""

    alias: str
    hostname: str
    user: str
    port: int
    identity_file: str
    known_hosts: str                       # per-profile UserKnownHostsFile (isolation)
    raw_options: dict[str, str] = field(default_factory=dict)


@lru_cache(maxsize=1)
def make_env() -> Environment:
    return Environment(
        loader=PackageLoader("ssh_manager", "templates"),
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_root_config(global_options: dict[str, str], *, emit_use_keychain: bool) -> str:
    """Render the top-level config; drop ``UseKeychain`` off macOS.

    The output is ssh-manager's *managed block* only (header ... end-marker). It is
    written into ``~/.ssh/config`` via :func:`compose_root_config`, which keeps any
    foreign content (e.g. an OrbStack ``Include`` that must sit at the very top)
    untouched - so reconcile never clobbers another tool's edits.
    """
    opts = {
        k: v for k, v in global_options.items()
        if not (k == "UseKeychain" and not emit_use_keychain)
    }
    tmpl = make_env().get_template("root_config.j2")
    return tmpl.render(global_options=opts, managed_header=MANAGED_HEADER,
                       managed_end=MANAGED_END)


def compose_root_config(existing: str | None, managed: str) -> str:
    """Return the full ``~/.ssh/config`` with ssh-manager's managed block in place,
    preserving any foreign content above and below it.

    ssh-manager owns only the region between :data:`MANAGED_HEADER` and
    :data:`MANAGED_END`. Anything before it (an OrbStack ``Include``, a hand-written
    preamble) and after it is carried through verbatim. An old-format file that has
    the header but no end-marker is migrated (its block ran to EOF). A file with no
    header at all is treated as entirely foreign - the managed block is appended.
    This is the single composer used by both ``config render`` and ``config check``.
    """
    if not existing:
        return managed
    lines = existing.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip() in _HEADERS), None)
    if start is None:
        preamble_lines, trailer_lines = lines, []
    else:
        preamble_lines = lines[:start]
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].strip() in _ENDS), None)
        trailer_lines = lines[end + 1:] if end is not None else []
    preamble = "\n".join(preamble_lines).rstrip("\n")
    trailer = "\n".join(trailer_lines).strip("\n")
    block = managed if managed.endswith("\n") else managed + "\n"
    out = (preamble + "\n\n" if preamble else "") + block
    if trailer:
        out += "\n" + trailer + "\n"
    return out


def render_profile_config(hosts: list[RenderHost]) -> str:
    """Render one ``profiles/<name>/config`` from its resolved hosts."""
    tmpl = make_env().get_template("profile_config.j2")
    return tmpl.render(hosts=hosts, managed_header=MANAGED_HEADER)


def render_all(manifest: Manifest, *, emit_use_keychain: bool) -> dict[str, str]:
    """Render every managed config file → {relative path: content}.

    Keys are paths relative to ``~/.ssh`` (``config`` and ``profiles/<p>/config``).
    Empty profiles render no file (``school`` placeholder).
    """
    out: dict[str, str] = {
        ROOT_CONFIG: render_root_config(
            manifest.defaults.global_options, emit_use_keychain=emit_use_keychain
        )
    }
    by_profile: dict[str, list[RenderHost]] = {}
    for rk in manifest.iter_resolved():
        by_profile.setdefault(rk.profile, []).append(
            RenderHost(
                alias=rk.host.alias,
                hostname=rk.host.hostname,
                user=rk.host.user,
                port=rk.host.port,
                identity_file=rk.identity_file,
                known_hosts=manifest.known_hosts_file(rk.profile),
                raw_options=rk.host.raw_options,
            )
        )
    for pname, hosts in by_profile.items():
        out[f"profiles/{pname}/config"] = render_profile_config(hosts)
    return out
