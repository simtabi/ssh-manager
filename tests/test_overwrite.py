"""keygen overwrite/skip: existing keys are warned + skipped by default; with an
overwrite set they regenerate (the Facade snapshots ~/.ssh first)."""
from __future__ import annotations

from pathlib import Path

from ssh_manager.platforms.macos import MacOS
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.keystore import KeyStore


def test_keystore_overwrite_regenerates(tmp_path: Path) -> None:
    ks = KeyStore(MacOS())
    p = tmp_path / "k"
    g1 = ks.generate(p)
    assert g1.created
    g2 = ks.generate(p)                                  # idempotent default
    assert not g2.created and g2.fingerprint == g1.fingerprint
    g3 = ks.generate(p, overwrite=True)                  # overwrite -> fresh key
    assert g3.created and g3.fingerprint != g1.fingerprint
    assert p.with_suffix(".pub").exists()


def test_existing_keys_reports_present(svc: SshManagerService) -> None:
    svc.reconcile()
    assert "work_unc-ed25519" in svc.existing_keys("work")
    assert svc.existing_keys("school") == []             # empty profile, nothing minted


def test_keygen_default_skips_existing(svc: SshManagerService) -> None:
    svc.reconcile()
    fp1 = svc.validate_keys("work_unc-ed25519")[0].fingerprint
    assert svc.keygen("work") == []                      # nothing minted (all present)
    assert svc.validate_keys("work_unc-ed25519")[0].fingerprint == fp1   # unchanged


def test_keygen_overwrite_regenerates_named_key(svc: SshManagerService) -> None:
    svc.reconcile()
    fp1 = svc.validate_keys("work_unc-ed25519")[0].fingerprint
    minted = svc.keygen("work", overwrite={"work_unc-ed25519"})
    assert [m.key_name for m in minted] == ["work_unc-ed25519"]
    fp2 = svc.validate_keys("work_unc-ed25519")[0].fingerprint
    assert fp2 != fp1                                     # regenerated
    # a snapshot of the pre-overwrite tree exists (backup strategy followed)
    assert svc.list_snapshots()
