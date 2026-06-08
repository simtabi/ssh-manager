"""Run-check / preflight. Detect OS + verify required tech.

Implemented for real so `sshmgr doctor` works from day one: it names missing
hard deps (actionable), notes optional ones that degrade gracefully, and warns
when the host OS is not yet first-class.
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field

from ..platforms import detect
from ..platforms.base import Platform

MIN_PYTHON = (3, 11)
HARD_BINS = ["ssh-keygen", "ssh-add", "ssh-copy-id", "ssh-keyscan"]
OPTIONAL_BINS = ["age", "sops", "gitleaks", "gh", "glab", "age-plugin-yubikey"]


@dataclass
class Report:
    os_name: str
    python_ok: bool
    os_first_class: bool = True
    missing_hard: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.python_ok and not self.missing_hard


def check(platform: Platform | None = None) -> Report:
    platform = platform or detect()
    rep = Report(
        os_name=f"{sys.platform} ({platform.name})",
        python_ok=sys.version_info[:2] >= MIN_PYTHON,
        os_first_class=platform.first_class,
    )
    rep.missing_hard = [b for b in HARD_BINS if shutil.which(b) is None]
    rep.missing_optional = [b for b in OPTIONAL_BINS if shutil.which(b) is None]
    return rep


def format_report(rep: Report) -> str:
    lines = [
        f"os: {rep.os_name}",
        f"python >= {'.'.join(map(str, MIN_PYTHON))}: {'ok' if rep.python_ok else 'FAIL'}",
    ]
    if not rep.os_first_class:
        lines.append("note: this OS is not yet first-class - support is in progress")
    lines.append(
        "hard deps: "
        + ("ok" if not rep.missing_hard else "MISSING " + ", ".join(rep.missing_hard))
    )
    if rep.missing_optional:
        lines.append("optional (degrade gracefully): " + ", ".join(rep.missing_optional))
    lines.append("RESULT: " + ("ready" if rep.ok else "blocked - run bootstrap.sh"))
    return "\n".join(lines)
