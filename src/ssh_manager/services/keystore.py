"""Key generation / fingerprinting - shells out to ssh-keygen.

Generation is non-destructive (invariant 15): an existing private key is never
clobbered; we just report its fingerprint. Perms are set immediately on create
through the platform layer (load-bearing - invariant 10).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..platforms.base import Platform
from ..util import perms, proc
from ..util.errors import ProcError

INSTALL_HINT = "install OpenSSH (macOS ships it; else: brew install openssh)"


@dataclass(frozen=True)
class GenResult:
    path: Path
    fingerprint: str
    created: bool   # False == already existed (idempotent re-run)


class KeyStore:
    def __init__(self, platform: Platform) -> None:
        self._platform = platform

    def generate(self, priv_path: Path, *, key_type: str = "ed25519",
                 comment: str = "", passphrase: str = "",
                 overwrite: bool = False) -> GenResult:
        """Mint a keypair at ``priv_path``. Idempotent + non-destructive by default
        (an existing key is kept); with ``overwrite=True`` the existing pair is
        removed and regenerated - callers MUST have snapshotted ~/.ssh first.

        Hardware ``*-sk`` types are attempted via ssh-keygen; if no FIDO2 device is
        present it gracefully falls back to the software equivalent."""
        if priv_path.exists() and not overwrite:
            return GenResult(priv_path, self.fingerprint(priv_path), created=False)
        if priv_path.exists():        # overwrite: drop the old pair so ssh-keygen won't prompt
            priv_path.unlink()
            priv_path.with_suffix(".pub").unlink(missing_ok=True)
        proc.require("ssh-keygen", INSTALL_HINT)
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        self._platform.set_perms(priv_path.parent, perms.DIR_MODE)
        result = proc.run([
            "ssh-keygen", "-t", key_type, "-f", str(priv_path),
            "-C", comment, "-N", passphrase, "-q",
        ])
        if result.returncode != 0 and key_type.endswith("-sk"):
            fallback = key_type[: -len("-sk")]   # ed25519-sk -> ed25519
            result = proc.run([
                "ssh-keygen", "-t", fallback, "-f", str(priv_path),
                "-C", f"{comment} (sk-fallback)", "-N", passphrase, "-q",
            ])
        if result.returncode != 0:
            raise ProcError(f"ssh-keygen failed: {result.stderr.strip()}")
        self._platform.set_perms(priv_path, perms.PRIVATE_KEY_MODE)
        self._platform.set_perms(priv_path.with_suffix(".pub"), perms.PUBLIC_KEY_MODE)
        return GenResult(priv_path, self.fingerprint(priv_path), created=True)

    def fingerprint(self, path: Path) -> str:
        """Return the ``SHA256:...`` fingerprint of a public or private key."""
        proc.require("ssh-keygen", INSTALL_HINT)
        out = proc.run_checked(["ssh-keygen", "-lf", str(path)]).stdout.strip()
        parts = out.split()
        if len(parts) < 2 or not parts[1].startswith("SHA256:"):
            raise ProcError(f"could not parse fingerprint from: {out!r}")
        return parts[1]

    def public_from_private(self, priv_path: Path) -> tuple[str | None, bool]:
        """Derive the public key *from the private key material* (``ssh-keygen -y``)
        - the only way to actually prove a keypair matches. Returns
        ``(public_line | None, encrypted)``: ``None`` with ``encrypted=True`` when
        the key is passphrase-protected (can't derive without it), ``None`` with
        ``encrypted=False`` when the private key is invalid/unreadable."""
        proc.require("ssh-keygen", INSTALL_HINT)
        # -P "" supplies an empty passphrase: succeeds for unencrypted keys,
        # fails cleanly (no prompt/hang) for encrypted ones.
        r = proc.run(["ssh-keygen", "-y", "-P", "", "-f", str(priv_path)])
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip(), False
        # Failed: distinguish "encrypted" (a valid key needing a passphrase) from
        # "invalid" by inspecting the file itself, not a locale-sensitive stderr
        # string - a real key file has a PRIVATE KEY header.
        try:
            head = priv_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, False
        return None, "PRIVATE KEY-----" in head
