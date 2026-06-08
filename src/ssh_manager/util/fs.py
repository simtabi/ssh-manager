"""Filesystem helpers: atomic text writes, tree creation, snapshots.

Atomic writes (temp + ``os.replace``) are mandatory for every key/config file
(invariant 11/15) so a crash mid-write never leaves a half file. Snapshots give a
local, reversible point-in-time backup of ``~/.ssh`` before any mutation.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from .errors import SshManagerError

SNAPSHOT_GLOB = "ssh-*.tar.gz"
_TMP_GLOB = ".*.tmp"


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create a directory (and parents) if absent, then enforce ``mode``."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    return path


def write_text_atomic(path: Path, text: str, mode: int = 0o600) -> None:
    """Write text via temp file + ``os.replace`` and chmod the result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        # newline="" so LF stays LF on every platform: ssh config and keys must be
        # LF, and it keeps the on-disk bytes deterministic (no CRLF on Windows).
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def clean_temp_artifacts(ssh_dir: Path) -> list[str]:
    """Sweep crash residue: leftover atomic-write temp files (``.<name>.*.tmp``)
    and any stray ``profiles/<p>/.staging/`` dir from a rotation that died before
    commit. Returns the relative paths removed. Scoped to our own prefixes so it
    never touches unrelated dotfiles.
    """
    if not ssh_dir.exists():
        return []
    removed: list[str] = []
    for tmp in ssh_dir.rglob(_TMP_GLOB):
        if tmp.is_file():
            tmp.unlink(missing_ok=True)
            removed.append(str(tmp.relative_to(ssh_dir)))
    profiles = ssh_dir / "profiles"
    if profiles.is_dir() and not profiles.is_symlink():
        for staging in profiles.glob("*/.staging"):
            if staging.is_dir() and not staging.is_symlink():
                shutil.rmtree(staging, ignore_errors=True)
                removed.append(str(staging.relative_to(ssh_dir)))
    return removed


def snapshot_ssh_dir(ssh_dir: Path, snapshots_dir: Path, *,
                     retain: int = 10, stamp: str | None = None) -> Path | None:
    """Tar ``ssh_dir`` into ``snapshots_dir`` and prune to the last ``retain``.

    Returns the snapshot path, or None if ``ssh_dir`` does not exist yet. The
    filename is made unique (``-1``, ``-2``...) so two snapshots in the same second
    never clobber each other.
    """
    if not ssh_dir.exists():
        return None
    if ssh_dir.is_symlink():
        raise SshManagerError(f"refusing to snapshot a symlinked {ssh_dir} "
                          "(it could point outside the managed tree)")
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(snapshots_dir, 0o700)
    stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = _unique_path(snapshots_dir / f"ssh-{stamp}.tar.gz")
    # Create the tarball owner-only BEFORE streaming private keys into it, so it's
    # never group/world-readable mid-write (a chmod after the write leaves a window).
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        tar.add(ssh_dir, arcname=ssh_dir.name)
    os.chmod(dest, 0o600)            # belt-and-suspenders (umask could have loosened)
    _prune_snapshots(snapshots_dir, retain)
    return dest


def _snap_sort_key(path: Path) -> tuple[int, str]:
    """Order snapshots by true creation time. A lexical sort of the names is wrong
    when two snapshots land in the same second: the collision suffix (``-1``/``-2``,
    char 0x2d) sorts *before* the base name's ``.`` (0x2e), so the base (oldest)
    would be picked as 'latest'. mtime is the real chronological order."""
    try:
        return (path.stat().st_mtime_ns, path.name)
    except OSError:
        return (0, path.name)


def list_snapshots(snapshots_dir: Path) -> list[Path]:
    """Snapshots oldest→newest (by creation time)."""
    if not snapshots_dir.is_dir():
        return []
    return sorted(snapshots_dir.glob(SNAPSHOT_GLOB), key=_snap_sort_key)


def restore_snapshot(tarball: Path, ssh_dir: Path) -> None:
    """Replace ``ssh_dir`` with the contents of ``tarball`` (exact restore).

    The caller is responsible for snapshotting the *current* tree first (so the
    restore is itself reversible). Extraction uses the ``data`` filter to reject
    path traversal. Perms are re-applied by the caller.
    """
    if not tarball.exists():
        raise SshManagerError(f"snapshot not found: {tarball}")
    if ssh_dir.name != ".ssh":
        raise SshManagerError(f"refusing to restore over a non-.ssh path: {ssh_dir}")
    if ssh_dir.is_symlink():
        raise SshManagerError(f"refusing to restore over a symlinked {ssh_dir} "
                          "(it could point outside the managed tree)")
    try:
        with tarfile.open(tarball, "r:gz") as tar:
            members = tar.getmembers()              # forces a read; fails early if corrupt
            if ssh_dir.exists():
                shutil.rmtree(ssh_dir)
            ssh_dir.parent.mkdir(parents=True, exist_ok=True)
            tar.extractall(ssh_dir.parent, members, filter="data")  # 'data' rejects traversal
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise SshManagerError(
            f"snapshot is corrupt or not a valid archive: {tarball}: {exc}") from exc


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    base = path.name[: -len(".tar.gz")]
    n = 1
    while True:
        cand = path.with_name(f"{base}-{n}.tar.gz")
        if not cand.exists():
            return cand
        n += 1


def _prune_snapshots(snapshots_dir: Path, retain: int) -> None:
    snaps = sorted(snapshots_dir.glob(SNAPSHOT_GLOB), key=_snap_sort_key)
    for old in snaps[:-retain] if retain > 0 else snaps:
        old.unlink(missing_ok=True)
