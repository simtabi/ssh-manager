"""Hardened generic-ssh remove: single locked remote read-modify-write.

These run the actual generated remote script locally (via `sh`) against a temp
``$HOME`` so the real shell logic - flock, body-match removal, lockout guard,
timestamped backup, atomic replace - is exercised, not mocked.
"""
from __future__ import annotations

import base64
import os
import struct
import subprocess
from pathlib import Path

from ssh_manager.providers.base import Target
from ssh_manager.providers.ssh_generic import GenericSSH


def _body(tag: bytes, key_type: bytes = b"ssh-ed25519") -> str:
    payload = (tag * 64)[:32]
    blob = struct.pack(">I", len(key_type)) + key_type + struct.pack(">I", 32) + payload
    return base64.b64encode(blob).decode()


TARGET = _body(b"target")
OTHER = _body(b"other", b"ssh-rsa")


class _Resp:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _run_remove_locally(tmp_path: Path, monkeypatch, initial: str):
    """Execute the remote `remove` script for real against a temp HOME."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    ak = home / ".ssh" / "authorized_keys"
    ak.write_text(initial)
    captured: dict[str, str] = {}

    def fake_run(cmd, timeout=None, **kw):
        script = cmd[-1]
        captured["script"] = script
        r = subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                            env={"HOME": str(home), "PATH": os.environ.get("PATH", "")})
        return _Resp(r.returncode, r.stdout, r.stderr)

    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.run", fake_run)
    pub = tmp_path / "k.pub"
    pub.write_text(f"ssh-ed25519 {TARGET} me@host\n")
    t = Target(alias="a", hostname="h", user="u", pubkey_path=pub,
               pubkey_text=pub.read_text())
    ok = GenericSSH().remove(t)
    return ok, ak, captured


def test_remove_keeps_other_keys_and_backs_up(tmp_path, monkeypatch) -> None:
    ok, ak, cap = _run_remove_locally(
        tmp_path, monkeypatch, f"ssh-ed25519 {TARGET} me@host\nssh-rsa {OTHER} you\n")
    assert ok is True
    text = ak.read_text()
    assert TARGET not in text                       # target removed
    assert OTHER in text                            # other key kept
    backups = list(ak.parent.glob("authorized_keys.ssh-manager.bak.*"))
    assert backups, "a timestamped backup must be taken before the rewrite"
    assert "flock" in cap["script"]                 # single locked remote op


def test_remove_lockout_guard_refuses_to_empty(tmp_path, monkeypatch) -> None:
    ok, ak, _ = _run_remove_locally(tmp_path, monkeypatch, f"ssh-ed25519 {TARGET} only\n")
    assert ok is False                              # removing the only key is refused
    assert TARGET in ak.read_text()                 # file left untouched


def test_remove_returns_false_when_key_absent(tmp_path, monkeypatch) -> None:
    ok, ak, _ = _run_remove_locally(tmp_path, monkeypatch, f"ssh-rsa {OTHER} you\n")
    assert ok is False
    assert OTHER in ak.read_text()                  # nothing changed


def test_remove_preserves_options_prefixed_other_key(tmp_path, monkeypatch) -> None:
    # an options-prefixed line is a real key line; the lockout guard must see it.
    initial = (f'command="x",no-pty ssh-rsa {OTHER} ops\n'
               f"ssh-ed25519 {TARGET} me@host\n")
    ok, ak, _ = _run_remove_locally(tmp_path, monkeypatch, initial)
    assert ok is True
    text = ak.read_text()
    assert TARGET not in text and OTHER in text


def test_remove_returns_false_on_unreachable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.run",
                        lambda cmd, **k: _Resp(returncode=255))   # ssh transport failed
    pub = tmp_path / "k.pub"
    pub.write_text(f"ssh-ed25519 {TARGET} me@host\n")
    t = Target(alias="a", hostname="h", user="u", pubkey_path=pub,
               pubkey_text=pub.read_text())
    assert GenericSSH().remove(t) is False
