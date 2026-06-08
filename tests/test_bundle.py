"""bundle/restore: .env exclusion, same-key recovery, checksum, age cmd."""
from __future__ import annotations

import stat
import tarfile
from pathlib import Path

import pytest

from ssh_manager.services.bundler import AgeCipher, Cipher
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.keystore import KeyStore
from ssh_manager.util.errors import DependencyError, SshManagerError


class FakeCipher(Cipher):
    """Reversible, no-age stand-in: prefixes a marker line so ciphertext != tar."""

    def encrypt_file(self, src: Path, dst: Path, *, recipient: str) -> None:
        dst.write_bytes(b"FAKEAGE:" + recipient.encode() + b"\n" + src.read_bytes())

    def decrypt_file(self, src: Path, dst: Path, *,
                     identity_file: Path | None, passphrase: str | None) -> None:
        data = src.read_bytes()
        dst.write_bytes(data[data.index(b"\n") + 1:])


def _members(age_path: Path) -> list[str]:
    """Decrypt with the fake cipher and list the tar members."""
    tar = age_path.with_suffix(".tar")
    FakeCipher().decrypt_file(age_path, tar, identity_file=None, passphrase=None)
    with tarfile.open(tar, "r:gz") as t:
        return t.getnames()


def test_bundle_excludes_env_and_writes_sidecars(svc: SshManagerService, tmp_path) -> None:
    svc.reconcile()
    (svc.paths.config_dir / ".env").write_text("GH_TOKEN=secret")   # must NOT be bundled
    out = tmp_path / "bundles"
    res = svc.bundle(recipient="age1testrecipient", output=out, cipher=FakeCipher())
    assert res.age_path.exists()
    assert (out / f"{res.age_path.name}.sha256").exists()
    assert (out / f"{res.age_path.name}.contents").exists()
    assert res.sha256.startswith("sha256:")
    # the encrypted tar contains keys + manifest/inventory/providers, never .env
    members = _members(res.age_path)
    assert any(m.startswith("ssh/profiles/work/work_unc-ed25519") for m in members)
    assert "config/manifest.json" in members
    assert "config/inventory.json" in members
    assert not any(".env" in m for m in members)
    assert not any(".env" in c for c in res.contents)


def test_bundle_omits_staging(svc: SshManagerService, tmp_path) -> None:
    svc.reconcile()
    staging = svc.paths.ssh_dir / "profiles/work/.staging"
    staging.mkdir(parents=True)
    (staging / "leftover").write_text("x")
    res = svc.bundle(recipient="age1x", output=tmp_path, cipher=FakeCipher())
    assert not any(".staging" in m for m in _members(res.age_path))


def test_restore_brings_back_the_same_keys(svc: SshManagerService, tmp_path) -> None:
    svc.reconcile()
    ks = KeyStore(svc.platform)
    key = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519"
    orig_fp = ks.fingerprint(key.with_suffix(".pub"))
    res = svc.bundle(recipient="age1x", output=tmp_path, cipher=FakeCipher())

    # simulate a wiped machine: remove the whole ~/.ssh
    import shutil
    shutil.rmtree(svc.paths.ssh_dir)

    restored = svc.restore(res.age_path, cipher=FakeCipher())
    assert key.exists() and key.with_suffix(".pub").exists()
    # SAME key (same fingerprint) - true recovery, not a fresh mint
    assert ks.fingerprint(key.with_suffix(".pub")) == orig_fp
    assert restored.fingerprints["work_unc-ed25519"] == orig_fp
    # perms re-asserted, config re-rendered from the restored manifest
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert (svc.paths.ssh_dir / "config").exists()
    assert svc.config_check().in_sync


def test_restore_refuses_on_checksum_mismatch(svc: SshManagerService, tmp_path) -> None:
    svc.reconcile()
    res = svc.bundle(recipient="age1x", output=tmp_path, cipher=FakeCipher())
    res.age_path.write_bytes(res.age_path.read_bytes() + b"corruption")  # tamper, sidecar stale
    with pytest.raises(SshManagerError, match="checksum mismatch"):
        svc.restore(res.age_path, cipher=FakeCipher())


def test_bundle_without_recipient_errors(svc: SshManagerService, tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SSH_MANAGER_AGE_RECIPIENT", raising=False)
    svc.reconcile()
    with pytest.raises(SshManagerError, match="no age recipient"):
        svc.bundle(recipient=None, output=tmp_path, cipher=FakeCipher())


def test_age_cipher_missing_age_is_clear(tmp_path, monkeypatch) -> None:
    # simulate age absent at the `which` level, so this holds whether or not age
    # is actually installed on the machine running the tests.
    monkeypatch.setattr("ssh_manager.util.proc.shutil.which", lambda b: None)
    with pytest.raises(DependencyError, match="age"):
        AgeCipher().encrypt_file(tmp_path / "a", tmp_path / "b", recipient="age1x")


def test_age_cipher_builds_commands(tmp_path, monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("ssh_manager.services.bundler.proc.require", lambda *a, **k: "/age")
    monkeypatch.setattr("ssh_manager.services.bundler.proc.run_checked",
                        lambda cmd, **k: calls.append(cmd))
    src, dst, ident = tmp_path / "in", tmp_path / "out", tmp_path / "id.txt"
    AgeCipher().encrypt_file(src, dst, recipient="age1abc")
    AgeCipher().decrypt_file(dst, src, identity_file=ident, passphrase=None)
    assert calls[0] == ["age", "-r", "age1abc", "-o", str(dst), str(src)]
    assert calls[1] == ["age", "-d", "-o", str(src), "-i", str(ident), str(dst)]
