"""Key validation (pub + private parse, pair match, perms) and provider listing."""
from __future__ import annotations

from ssh_manager.services.facade import SshManagerService


def test_validate_passes_for_freshly_minted_keys(svc: SshManagerService) -> None:
    svc.reconcile()
    checks = svc.validate_keys()
    assert checks and all(c.ok for c in checks)          # all healthy
    assert all(c.fingerprint and c.fingerprint.startswith("SHA256:") for c in checks)


def test_validate_flags_corrupt_public_key(svc: SshManagerService) -> None:
    svc.reconcile()
    (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519.pub").write_text("garbage\n")
    check = next(c for c in svc.validate_keys("work_unc-ed25519"))
    assert not check.ok
    assert any("malformed" in i for i in check.issues)


def test_validate_flags_mismatched_pair(svc: SshManagerService) -> None:
    svc.reconcile()
    # overwrite the .pub with a *different* (but valid) key -> pair must not match
    other = (svc.paths.ssh_dir / "profiles/personal/personal_github-ed25519.pub").read_text()
    (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519.pub").write_text(other)
    check = next(c for c in svc.validate_keys("work_unc-ed25519"))
    assert not check.ok
    assert any("does NOT match" in i for i in check.issues)


def test_validate_flags_bad_perms(svc: SshManagerService) -> None:
    svc.reconcile()
    (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519").chmod(0o644)   # too open
    check = next(c for c in svc.validate_keys("work_unc-ed25519"))
    assert not check.ok
    assert any("perms" in i for i in check.issues)


def test_validate_encrypted_key_is_noted_not_failed(svc: SshManagerService) -> None:
    svc.reconcile(passphrase="secret")                   # passphrase-protected keys
    check = next(c for c in svc.validate_keys("work_unc-ed25519"))
    assert check.ok                                      # encrypted is valid, not a failure
    assert any("encrypted" in n for n in check.notes)    # but the pair couldn't be verified


def test_validate_selector_filters_by_profile(svc: SshManagerService) -> None:
    svc.reconcile()
    checks = svc.validate_keys("work")
    assert checks and all(c.profile == "work" for c in checks)


def test_list_providers_reports_credential_presence(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "tok")
    monkeypatch.delenv("VULTR_API_KEY", raising=False)
    infos = {p.name: p for p in svc.list_providers()}
    assert infos["digitalocean"].token_present is True
    assert infos["vultr"].token_present is False
    assert infos["digitalocean"].category == "vps"
