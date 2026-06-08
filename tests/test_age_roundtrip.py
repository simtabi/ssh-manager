"""Real `age` encrypt -> decrypt round-trip (skipped if age isn't installed).

Complements test_bundle.py (which uses a FakeCipher for the logic): this proves
the AgeCipher argv actually encrypts and that a bundle restores the SAME bytes.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ssh_manager.services.facade import SshManagerService
from ssh_manager.util.errors import SshManagerError

pytestmark = pytest.mark.skipif(
    shutil.which("age") is None or shutil.which("age-keygen") is None,
    reason="age / age-keygen not installed",
)


def _age_identity(out_dir: Path) -> tuple[Path, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ident = out_dir / "id.txt"
    r = subprocess.run(["age-keygen", "-o", str(ident)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    recipient = next(
        (ln.split(":", 1)[1].strip() for ln in ident.read_text().splitlines()
         if ln.lower().startswith("# public key:")), "")
    assert recipient.startswith("age1")
    return ident, recipient


def test_real_age_bundle_restore_roundtrip(svc: SshManagerService, tmp_path: Path) -> None:
    svc.reconcile()
    ident, recipient = _age_identity(tmp_path / "key")
    dest = tmp_path / "backups"
    dest.mkdir()

    bundle = svc.bundle(recipient=recipient, output=dest).age_path   # real AgeCipher (default)
    assert bundle.exists() and bundle.suffix == ".age"
    assert bundle.read_bytes().startswith(b"age-encryption.org/v1")  # genuinely encrypted

    key = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    orig = key.read_bytes()
    key.unlink()
    key.with_suffix(".pub").unlink()

    svc.restore(bundle, identity_file=ident)                         # real decrypt
    assert key.exists()
    assert key.read_bytes() == orig                                 # SAME key bytes recovered


def test_real_age_wrong_identity_is_rejected(svc: SshManagerService, tmp_path: Path) -> None:
    svc.reconcile()
    _, recipient = _age_identity(tmp_path / "right")
    bundle = svc.bundle(recipient=recipient, output=tmp_path).age_path
    wrong_ident, _ = _age_identity(tmp_path / "wrong")
    with pytest.raises(SshManagerError):
        svc.restore(bundle, identity_file=wrong_ident)              # can't decrypt
