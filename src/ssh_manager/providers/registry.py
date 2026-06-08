"""Provider registry - config-driven (pluggable, nothing hardcoded).

A provider name resolves through ``config/providers.json`` to a ProviderSpec, and
the spec's ``kind`` selects the adapter class. The SAME adapter serves cloud and
enterprise/self-hosted instances - they're just different specs (different host).
So *any* VCS works: github/gitlab get CLI automation; everything else falls back
to the universal web-panel/manual path with the correct per-instance keys URL.

Resolution order: named instance → generic SSH fallback for an unknown name.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..util import jsonstore
from .base import Provider, ProviderSpec
from .cloud import DigitalOcean, GenericRest, Hetzner, Linode, Scaleway, Vultr
from .github import GitHub
from .gitlab import GitLab
from .ssh_generic import GenericSSH

# kind -> adapter class. github/gitlab automate via CLI; the cloud VPS kinds manage
# account keys via REST; everything else (web-panel, and any unlisted vcs kind like
# bitbucket/gitea/sourcehut) uses the base Provider - the universal manual path
# using the keys URL from its spec.
_ADAPTERS: dict[str, type[Provider]] = {
    "github": GitHub,
    "gitlab": GitLab,
    "ssh": GenericSSH,
    "web-panel": Provider,
    "digitalocean": DigitalOcean,
    "vultr": Vultr,
    "hetzner": Hetzner,
    "linode": Linode,
    "scaleway": Scaleway,
    "rest": GenericRest,    # config-driven: define any REST provider in providers.json
}

# Sensible built-in defaults so the tool works before providers.json is consulted.
_BUILTIN_SPECS: dict[str, ProviderSpec] = {
    "github": ProviderSpec("github", kind="github", category="vcs",
                           host="github.com", cli="gh", token_env="GH_TOKEN"),
    "gitlab": ProviderSpec("gitlab", kind="gitlab", category="vcs",
                           host="gitlab.com", cli="glab", token_env="GLAB_TOKEN"),
    "ploi": ProviderSpec("ploi", kind="web-panel", category="panel",
                         keys_url="https://ploi.io/servers"),
    "generic-ssh": ProviderSpec("generic-ssh", kind="ssh", category="server"),
    "digitalocean": ProviderSpec("digitalocean", kind="digitalocean", category="vps",
                                 token_env="DIGITALOCEAN_TOKEN"),
    "vultr": ProviderSpec("vultr", kind="vultr", category="vps", token_env="VULTR_API_KEY"),
    "hetzner": ProviderSpec("hetzner", kind="hetzner", category="vps", token_env="HCLOUD_TOKEN"),
    "linode": ProviderSpec("linode", kind="linode", category="vps", token_env="LINODE_TOKEN"),
    "scaleway": ProviderSpec("scaleway", kind="scaleway", category="vps",
                             token_env="SCW_SECRET_KEY"),
}


def resolve(name: str | None, providers_file: Path | None = None) -> Provider:
    """Resolve a provider name to an adapter instance for its instance spec."""
    if not name:
        return GenericSSH(_BUILTIN_SPECS["generic-ssh"])
    spec = _spec_for(name, providers_file)
    if spec is None:
        return GenericSSH(_BUILTIN_SPECS["generic-ssh"])
    cls = _ADAPTERS.get(spec.kind)
    if cls is None:
        # Unknown vcs/panel kind → universal web-panel/manual via the base Provider.
        return Provider(spec)
    return cls(spec)


def category_of(name: str | None, providers_file: Path | None = None) -> str:
    return resolve(name, providers_file).category


def all_specs(providers_file: Path | None = None) -> dict[str, ProviderSpec]:
    """Every known provider spec, by name. Layered: built-in minimal specs, then
    the resolved catalog (the user's providers.json if present, else the shipped
    package default), the later overriding the earlier."""
    specs = dict(_BUILTIN_SPECS)
    for name, entry in _providers_of(_load_catalog(providers_file)).items():
        if isinstance(entry, dict):
            specs[name] = _spec_from_entry(name, entry)
    return specs


# Parsed-catalog cache keyed by (source, mtime) so resolve()/category_of over an
# N-host manifest doesn't re-read+parse the JSON N times. Invalidates when a user
# file's mtime changes; the packaged default is keyed once (stable).
_CATALOG_CACHE: dict[tuple[str, int, int], Any] = {}


def _load_catalog(providers_file: Path | None) -> Any:
    """The effective providers catalog: the user's ``providers.json`` if present,
    else the default shipped with the package (``ssh_manager/data/providers.json``, kept
    byte-identical to the repo ``config/providers.json``). So the full catalog works
    out of the box; a user only creates their own file to customize it. Memoized by
    (path, mtime, size) - size guards an in-tick edit on coarse-mtime filesystems."""
    if providers_file is not None and providers_file.exists():
        try:
            st = providers_file.stat()
            key: tuple[str, int, int] | None = (str(providers_file), st.st_mtime_ns, st.st_size)
        except OSError:
            key = None
        if key is not None and key in _CATALOG_CACHE:
            return _CATALOG_CACHE[key]
        try:
            data = jsonstore.read_json(providers_file)
        except (ValueError, OSError):
            data = {}
        if key is not None:
            _CATALOG_CACHE[key] = data
        return data
    key = ("<packaged>", 0, 0)
    if key in _CATALOG_CACHE:
        return _CATALOG_CACHE[key]
    try:
        from importlib.resources import files
        text = (files("ssh_manager") / "data" / "providers.json").read_text(encoding="utf-8")
        data = json.loads(text)
    except (FileNotFoundError, OSError, ValueError, ModuleNotFoundError, TypeError):
        data = {}
    _CATALOG_CACHE[key] = data
    return data


def _providers_of(data: Any) -> dict[str, Any]:
    """The ``providers`` map from a parsed providers.json, tolerating a file that
    is valid JSON but the wrong shape (a list/scalar, or a non-dict ``providers``)."""
    if not isinstance(data, dict):
        return {}
    providers = data.get("providers", {})
    return providers if isinstance(providers, dict) else {}


def _spec_for(name: str, providers_file: Path | None) -> ProviderSpec | None:
    # The user's catalog if present, else the shipped default; then built-ins.
    entry = _providers_of(_load_catalog(providers_file)).get(name)
    if isinstance(entry, dict):
        return _spec_from_entry(name, entry)
    return _BUILTIN_SPECS.get(name)


def _spec_from_entry(name: str, entry: dict[str, Any]) -> ProviderSpec:
    return ProviderSpec(
        name=name,
        kind=str(entry.get("kind", "generic")),
        category=str(entry.get("category", "generic")),
        host=entry.get("host"),
        api_base=entry.get("api"),
        keys_url=entry.get("keys_url") or entry.get("manage_url"),
        cli=entry.get("cli"),
        token_env=entry.get("token_env"),
        rest=entry.get("rest"),     # generic REST config for kind 'rest'
    )
