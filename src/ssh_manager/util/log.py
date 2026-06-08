"""Logging + append-only audit log.

The audit log is an accountability record of create/deploy/rotate/delete with
timestamps. It lives under ``<home>/log/`` and is gitignored. It can contain key
names / fingerprints / paths, so it's created owner-only (0700 dir, 0600 file)
the moment it first appears - never momentarily world-readable before a perms pass.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("ssh_manager")

# Never record a value under one of these field names (defensive: callers pass
# only key names/fingerprints today, but the **fields sink is open-ended).
_SECRET_FIELDS = ("passphrase", "password", "token", "secret", "key_material")


def _redact(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***" if any(s in k.lower() for s in _SECRET_FIELDS) else v)
            for k, v in fields.items()}


def audit(audit_log: Path, event: str, **fields: Any) -> None:
    """Append one JSON line to the audit log (and mirror to the logger)."""
    fields = _redact(fields)
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "event": event,
        **fields,
    }
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(audit_log.parent, 0o700)
    new = not audit_log.exists()
    with open(audit_log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    if new:
        with contextlib.suppress(OSError):
            os.chmod(audit_log, 0o600)
    logger.info("audit %s %s", event, fields)
