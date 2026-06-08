"""Atomic, versioned JSON read/write (State integrity)."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> Any:
    """Parse a JSON file into Python objects."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json_atomic(path: str | Path, data: Any) -> None:
    """Write via temp file + os.replace so a crash never leaves a half file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)        # owner-only (manifest/inventory live in the home)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
