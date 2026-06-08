"""ssh-agent / macOS keychain integration.

Adds keys to the running ssh-agent; on macOS uses ``--apple-use-keychain`` so a
passphrase is stored once. Interactive so a passphrase prompt can be answered.
"""
from __future__ import annotations

from pathlib import Path

from ..util import proc

_HINT = "install OpenSSH (macOS ships it; else: brew install openssh)"


class Agent:
    def __init__(self, *, use_keychain: bool = False) -> None:
        self._use_keychain = use_keychain

    def add(self, key_path: Path) -> bool:
        """Add one private key to the agent. Returns True on success."""
        proc.require("ssh-add", _HINT)
        cmd = ["ssh-add"]
        if self._use_keychain:
            cmd.append("--apple-use-keychain")
        cmd.append(str(key_path))
        return proc.run_interactive(cmd) == 0
