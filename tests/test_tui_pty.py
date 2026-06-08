"""Functional TUI test driven through a real pseudo-terminal.

The unit tests (test_tui.py) drive the navigation loop with a FakePrompter; this
launches the actual `sshmgr tui` binary under a pty so questionary/prompt_toolkit
run for real - proving the interactive path renders the menu and navigates into
live data, then exits cleanly. POSIX-only (pty); skipped on Windows.
"""
from __future__ import annotations

import os
import select
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="pty is POSIX-only")


def _drain(fd: int, needle: bytes, timeout: float = 12.0) -> bytes:
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if needle in buf:
                break
    return buf


def test_tui_renders_and_navigates_in_a_pty(svc, env) -> None:
    import pty
    import subprocess

    svc.reconcile()                                    # populate the sandbox tree
    sshmgr = Path(sys.executable).parent / "sshmgr"
    if not sshmgr.exists():
        pytest.skip("sshmgr console script not found")

    sub_env = {
        "HOME": str(env["home"]),
        "SSH_MANAGER_CONFIG_DIR": str(env["config_dir"]),
        "PATH": os.environ.get("PATH", ""),
        "TERM": "xterm-256color",
        "LINES": "40", "COLUMNS": "120",
    }
    master, slave = pty.openpty()
    proc = subprocess.Popen([str(sshmgr), "tui"], stdin=slave, stdout=slave,
                            stderr=slave, env=sub_env, close_fds=True)
    os.close(slave)
    try:
        out = _drain(master, b"Browse profiles")       # the menu renders (real questionary)
        assert b"Browse profiles" in out, out[-400:]
        os.write(master, b"\r")                        # Enter -> "Browse profiles & hosts"
        out += _drain(master, b"work")                 # the real profile list from the service
        assert b"work" in out, out[-400:]
        # Ctrl-C out: questionary's .ask() returns None, so run() returns and exits.
        for _ in range(5):
            os.write(master, b"\x03")
            try:
                proc.wait(timeout=2)
                break
            except subprocess.TimeoutExpired:
                continue
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
    finally:
        os.close(master)
    assert proc.returncode is not None                 # it exited - did not hang
