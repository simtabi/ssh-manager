"""Permission constants + classification.

Perms are load-bearing - SSH refuses keys/config with loose modes. Application
goes through the platform layer (``platform.set_perms``); this module owns the
canonical constants, the path→mode policy, and the single enumeration of
tool-managed paths that BOTH reconcile (the fixer) and doctor (the checker) walk
- so they can never disagree, and neither touches unrelated user files.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

DIR_MODE = 0o700
PRIVATE_KEY_MODE = 0o600
CONFIG_MODE = 0o600
PUBLIC_KEY_MODE = 0o644


def mode_for(path: Path) -> int:
    """Return the canonical mode for a path by its role."""
    if path.is_dir():
        return DIR_MODE
    name = path.name
    if name == "config":
        return CONFIG_MODE
    if name.endswith(".pub") or name == "known_hosts":
        return PUBLIC_KEY_MODE          # host public keys - not secret
    return PRIVATE_KEY_MODE


def iter_managed_paths(ssh_dir: Path) -> Iterator[tuple[Path, int]]:
    """Yield (path, canonical_mode) for every tool-managed path under ``ssh_dir``.

    Managed = ``~/.ssh`` itself, the root ``config``, and the entire ``profiles/``
    subtree. Deliberately excludes unrelated files a user keeps in ``~/.ssh``
    (``id_rsa``, ``known_hosts``, agent sockets) so enforcement never clobbers
    them. Symlinks are skipped (we don't chmod through a link).
    """
    if not ssh_dir.exists() or ssh_dir.is_symlink():
        return
    yield ssh_dir, DIR_MODE
    root_config = ssh_dir / "config"
    if root_config.exists() and not root_config.is_symlink():
        yield root_config, CONFIG_MODE
    profiles = ssh_dir / "profiles"
    if profiles.is_dir() and not profiles.is_symlink():
        yield profiles, DIR_MODE
        for path in sorted(profiles.rglob("*")):
            if path.is_symlink():
                continue
            # Skip OS cruft + transient dirs (.DS_Store, .staging) - not ours to chmod.
            if any(part.startswith(".") for part in path.relative_to(profiles).parts):
                continue
            yield path, mode_for(path)
