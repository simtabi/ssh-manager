"""age bundle / restore - encrypted backup + true recovery.

`bundle` tars {private keys + manifest + inventory + providers.json}, age-encrypts
it to a single ``ssh-manager-YYYYMMDD.age`` with a SHA256 checksum and a plaintext
contents manifest. ``.env`` is **excluded** (it holds the recipient/identity refs
that unlock the bundle - bundling it would be circular). `restore` decrypts and
lays the **same** keys back down (same fingerprint), fixes perms, re-renders the
config, and loads the agent - true recovery, contrast with `reconcile` (§3).

The cipher is behind a small seam (``Cipher``): production uses ``AgeCipher``
(shells to ``age``); tests inject a fake so the tar / lay-down / fingerprint
guarantees are verifiable without ``age`` installed.
"""
from __future__ import annotations

import abc
import contextlib
import hashlib
import os
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..util import proc
from ..util.errors import SshManagerError

Fingerprinter = Callable[[Path], str]

AGE_HINT = "install age: brew install age  (Linux: apt install age / get from FiloSottile/age)"
SSH_PREFIX = "ssh/"
CONFIG_PREFIX = "config/"
CONFIG_MEMBERS = ("manifest.json", "inventory.json", "providers.json")


class Cipher(abc.ABC):
    @abc.abstractmethod
    def encrypt_file(self, src: Path, dst: Path, *, recipient: str) -> None: ...

    @abc.abstractmethod
    def decrypt_file(self, src: Path, dst: Path, *,
                     identity_file: Path | None, passphrase: str | None) -> None: ...


class AgeCipher(Cipher):
    """Shells out to ``age`` (X25519 + ChaCha20-Poly1305). File-based, so no
    binary pipes; supports recipient mode (and passphrase mode as a fallback)."""

    def encrypt_file(self, src: Path, dst: Path, *, recipient: str) -> None:
        proc.require("age", AGE_HINT)
        proc.run_checked(["age", "-r", recipient, "-o", str(dst), str(src)])

    def decrypt_file(self, src: Path, dst: Path, *,
                     identity_file: Path | None, passphrase: str | None) -> None:
        proc.require("age", AGE_HINT)
        cmd = ["age", "-d", "-o", str(dst)]
        if identity_file is not None:
            cmd += ["-i", str(identity_file)]
        cmd.append(str(src))
        # passphrase mode (no identity) prompts interactively; recipient mode is
        # the recommended default.
        proc.run_checked(cmd)


@dataclass
class BundleResult:
    age_path: Path
    sha256: str
    contents: list[str] = field(default_factory=list)

    def format(self) -> str:
        lines = [f"bundle: {self.age_path}",
                 f"  sha256: {self.sha256}",
                 f"  contents ({len(self.contents)} files; .env excluded):"]
        lines += [f"    {c}" for c in self.contents]
        return "\n".join(lines)


@dataclass
class RestoreResult:
    restored: list[str] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)  # key_name -> SHA256

    def format(self) -> str:
        lines = [f"restore: laid down {len(self.restored)} file(s)"]
        for name, fp in self.fingerprints.items():
            lines.append(f"  {name}  {fp}")
        return "\n".join(lines)


class Bundler:
    def __init__(self, ssh_dir: Path, config_dir: Path, cipher: Cipher) -> None:
        self._ssh = ssh_dir
        self._config = config_dir
        self._cipher = cipher

    # bundle
    def bundle(self, *, recipient: str, dest_dir: Path, stamp: str) -> BundleResult:
        if not recipient:
            raise SshManagerError(
                "no age recipient - set SSH_MANAGER_AGE_RECIPIENT or pass --recipient"
            )
        dest_dir.mkdir(parents=True, exist_ok=True)
        contents: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "bundle.tar.gz"
            contents = self._build_tar(tar_path)
            age_path = dest_dir / f"ssh-manager-{stamp}.age"
            self._cipher.encrypt_file(tar_path, age_path, recipient=recipient)
        sha = _sha256(age_path)
        (dest_dir / f"{age_path.name}.sha256").write_text(
            f"{sha}  {age_path.name}\n", encoding="utf-8"
        )
        (dest_dir / f"{age_path.name}.contents").write_text(
            "\n".join(contents) + "\n", encoding="utf-8"
        )
        return BundleResult(age_path=age_path, sha256=sha, contents=contents)

    def _build_tar(self, tar_path: Path) -> list[str]:
        members: list[str] = []
        with tarfile.open(tar_path, "w:gz") as tar:
            profiles = self._ssh / "profiles"
            if profiles.is_dir():
                for path in sorted(profiles.rglob("*")):
                    if path.is_dir() or ".staging" in path.parts:
                        continue
                    arc = SSH_PREFIX + str(path.relative_to(self._ssh))
                    tar.add(path, arcname=arc)
                    members.append(arc)
            for name in CONFIG_MEMBERS:                 # NEVER .env
                src = self._config / name
                if src.exists():
                    arc = CONFIG_PREFIX + name
                    tar.add(src, arcname=arc)
                    members.append(arc)
        return members

    # restore
    def restore(self, bundle_path: Path, *, identity_file: Path | None,
                passphrase: str | None, fingerprint_of: Fingerprinter) -> RestoreResult:
        if not bundle_path.exists():
            raise SshManagerError(f"bundle not found: {bundle_path}")
        self._verify_checksum(bundle_path)
        res = RestoreResult()
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "bundle.tar.gz"
            self._cipher.decrypt_file(bundle_path, tar_path,
                                      identity_file=identity_file, passphrase=passphrase)
            extract = Path(tmp) / "x"
            try:
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(extract, filter="data")  # 'data' rejects traversal
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise SshManagerError(
                    "bundle is corrupt or not a valid archive - check the "
                    f"identity/recipient: {exc}") from exc
            res.restored = self._lay_down(extract, res, fingerprint_of)
        return res

    def _lay_down(self, extract: Path, res: RestoreResult,
                  fingerprint_of: Fingerprinter) -> list[str]:
        laid: list[str] = []
        ssh_root = extract / "ssh"
        if ssh_root.is_dir():
            for path in sorted(ssh_root.rglob("*")):
                if path.is_dir():
                    continue
                dest = self._ssh / path.relative_to(ssh_root)
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                # Private keys: write owner-only AND atomically (mkstemp is 0600),
                # never via write_bytes (which would create them world/group-readable
                # at the default umask until the facade's perms pass runs).
                _write_bytes_atomic(dest, path.read_bytes())
                laid.append(str(dest.relative_to(self._ssh)))
                if dest.name.endswith(".pub"):
                    with contextlib.suppress(Exception):
                        res.fingerprints[dest.stem] = fingerprint_of(dest)
        cfg_root = extract / "config"
        if cfg_root.is_dir():
            for path in sorted(cfg_root.iterdir()):
                if path.is_file():
                    _write_bytes_atomic(self._config / path.name, path.read_bytes())
                    laid.append(f"config/{path.name}")
        return laid

    def _verify_checksum(self, bundle_path: Path) -> None:
        sidecar = bundle_path.with_name(bundle_path.name + ".sha256")
        if not sidecar.exists():
            return
        parts = sidecar.read_text(encoding="utf-8").split()
        if not parts:
            return                       # empty/blank sidecar - nothing to verify against
        want = parts[0]
        got = _sha256(bundle_path)
        if want != got:
            raise SshManagerError(
                f"bundle checksum mismatch: expected {want}, got {got} - refusing to restore"
            )


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()
