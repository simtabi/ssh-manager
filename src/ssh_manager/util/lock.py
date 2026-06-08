"""Advisory file lock so commands + notifier can't corrupt state."""
from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import IO


def secure_mkdir(path: Path) -> None:
    """Create ``path`` (and parents) restricted to the owner (0700). ``mkdir``'s
    mode is masked by umask, so chmod afterwards to guarantee no group/other bits
    - the dir holds the lock + caches that sit beside secrets."""
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):   # no-op on Windows ACL filesystems
        os.chmod(path, 0o700)


@contextlib.contextmanager
def advisory_lock(lock_path: str | Path) -> Iterator[IO[str]]:
    """Exclusive advisory lock: ``fcntl`` on POSIX, ``msvcrt`` on Windows."""
    lock_path = Path(lock_path)
    secure_mkdir(lock_path.parent)
    new = not lock_path.exists()
    fh = open(lock_path, "a+")  # noqa: SIM115 - held for the context's lifetime
    if new:
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)
    try:
        _flock(fh, lock=True)
        yield fh
    finally:
        _flock(fh, lock=False)
        fh.close()


def _flock(fh: IO[str], *, lock: bool) -> None:
    """Take/release an exclusive lock on ``fh`` using whatever the OS provides."""
    try:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX if lock else fcntl.LOCK_UN)
        return
    except ImportError:
        pass
    try:  # pragma: no cover - exercised only on Windows
        import msvcrt
        fh.seek(0)
        mode = msvcrt.LK_LOCK if lock else msvcrt.LK_UNLCK  # type: ignore[attr-defined]
        msvcrt.locking(fh.fileno(), mode, 1)  # type: ignore[attr-defined]
    except (ImportError, OSError):  # pragma: no cover - no backend / already-unlocked
        pass
