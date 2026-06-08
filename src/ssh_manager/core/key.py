"""Key value objects + the naming convention.

Name grammar: ``<profile>_<service>-<algo>`` - exactly one underscore (profile
prefix); the remainder is kebab-case. profile/service are normalized to lowercase
kebab; the algo suffix follows ssh-keygen (``ed25519``, ``ed25519-sk``, ``rsa``).
"""
from __future__ import annotations

import re


def normalize_segment(value: str) -> str:
    """Lowercase and collapse any non-alphanumeric run to a single dash."""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def build_key_name(profile: str, service: str, algo: str = "ed25519") -> str:
    """Build a canonical key name. Profile must reduce to a single token."""
    prof = normalize_segment(profile).replace("-", "")
    svc = normalize_segment(service)
    if not prof or not svc:
        raise ValueError(f"cannot build key name from profile={profile!r} service={service!r}")
    return f"{prof}_{svc}-{algo}"


def split_key_name(name: str) -> tuple[str, str]:
    """Split into (profile, remainder) on the first underscore."""
    profile, _, remainder = name.partition("_")
    if not remainder:
        raise ValueError(f"not a ssh-manager key name: {name!r}")
    return profile, remainder


# Known algo suffixes, longest first so ``-ed25519-sk`` wins over ``-sk``.
_ALGO_SUFFIXES = ("ed25519-sk", "ecdsa-sk", "ed25519", "ecdsa", "rsa", "dsa")


def algo_of(name: str) -> str:
    """Return the trailing ``-<algo>`` token of a key name (default ed25519)."""
    _, remainder = split_key_name(name)
    for algo in _ALGO_SUFFIXES:
        if remainder == algo or remainder.endswith("-" + algo):
            return algo
    return "ed25519"


def derive_key_name(profile: str, alias: str, algo: str = "ed25519") -> str:
    """Derive a canonical key name from a profile + a host alias.

    The alias is the service token (e.g. ``oribi-db-psql`` or ``sc.its.unc.edu``);
    normalization collapses dots/underscores to dashes (``...unc.edu`` → ``unc-edu``).
    """
    return build_key_name(profile, alias, algo)
