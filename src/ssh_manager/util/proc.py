"""Subprocess helpers - the single chokepoint for shelling out (invariant 14).

Never ``shell=True`` with interpolated input; callers always pass an argv list.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from .errors import DependencyError, ProcError


def _merged_env(env: dict[str, str] | None) -> dict[str, str] | None:
    """Overlay ``env`` onto the current process env (so PATH etc. survive)."""
    if env is None:
        return None
    merged = dict(os.environ)
    merged.update(env)
    return merged


TIMEOUT_RC = 124   # matches coreutils `timeout`


def run(cmd: list[str], *, input_: str | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing output. Callers decide on check semantics. A
    ``timeout`` that fires is turned into a clean rc-124 result (never a raised
    exception), so a wedged network command can't hang or crash the caller."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, input=input_, timeout=timeout,
            env=_merged_env(env), check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, TIMEOUT_RC, stdout="", stderr=f"timed out after {timeout}s",
        )


def run_checked(cmd: list[str], *, input_: str | None = None,
                timeout: float | None = None,
                env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command and raise ProcError on a non-zero exit."""
    proc = run(cmd, input_=input_, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise ProcError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc


def run_interactive(cmd: list[str], *, timeout: float | None = None,
                    env: dict[str, str] | None = None) -> int:
    """Run a command inheriting the terminal (no capture) - for tools that may
    prompt, e.g. ``ssh-copy-id`` asking for a password. Returns the exit code
    (or rc-124 if a ``timeout`` fires, so a wedged connection can't hang)."""
    try:
        return subprocess.run(cmd, env=_merged_env(env), check=False,
                              timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return TIMEOUT_RC


def require(binary: str, install_hint: str) -> str:
    """Resolve a hard-dependency binary or raise a clear DependencyError."""
    path = shutil.which(binary)
    if path is None:
        raise DependencyError(binary, install_hint)
    return path


def has(binary: str) -> bool:
    """True if an (optional) binary is on PATH."""
    return shutil.which(binary) is not None
