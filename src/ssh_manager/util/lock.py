"""Advisory file lock so commands + notifier can't corrupt state."""
from __future__ import annotations

import contextlib
import os
import sys
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


# Split by platform so mypy analyzes each branch against the right stdlib surface
# (``fcntl`` is POSIX-only, ``msvcrt`` Windows-only); ``sys.platform`` is the guard
# mypy narrows on, so neither branch needs a ``type: ignore``.
if sys.platform == "win32":
    import msvcrt

    def _flock(fh: IO[str], *, lock: bool) -> None:
        """Take/release an exclusive lock on ``fh`` using Windows ``msvcrt`` locking."""
        try:  # pragma: no cover - exercised only on Windows
            fh.seek(0)
            mode = msvcrt.LK_LOCK if lock else msvcrt.LK_UNLCK
            msvcrt.locking(fh.fileno(), mode, 1)
        except OSError:  # pragma: no cover - already-unlocked / lock contention
            pass
else:
    import fcntl

    def _flock(fh: IO[str], *, lock: bool) -> None:
        """Take/release an exclusive lock on ``fh`` using POSIX ``fcntl.flock``."""
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX if lock else fcntl.LOCK_UN)
