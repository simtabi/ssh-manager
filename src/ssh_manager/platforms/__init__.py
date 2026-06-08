"""OS detection + per-OS strategy. macOS first-class; Linux next; Windows later."""
from __future__ import annotations

import sys

from .base import Platform


def detect() -> Platform:
    if sys.platform == "darwin":
        from .macos import MacOS
        return MacOS()
    if sys.platform.startswith("linux"):
        from .linux import Linux
        return Linux()
    if sys.platform.startswith("win"):
        from .windows import Windows
        return Windows()
    # Unknown: fall back to POSIX behaviour but warn upstream.
    from .linux import Linux
    return Linux()
