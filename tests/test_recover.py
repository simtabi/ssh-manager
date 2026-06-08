"""Break-glass recovery: full tool + tailored per-key snippet."""
from __future__ import annotations

import pytest

from ssh_manager.services.facade import SshManagerService
from ssh_manager.util.errors import SshManagerError


def test_recover_emits_interactive_tool(svc: SshManagerService) -> None:
    script = svc.recovery_script()
    assert "authorized_keys recovery" in script
    assert "/dev/tty" in script                 # paste-into-console trick


def test_recover_missing_tool_raises_clean_error(svc: SshManagerService, monkeypatch) -> None:
    def boom(name: str) -> str:
        raise FileNotFoundError(name)
    monkeypatch.setattr("ssh_manager.services.facade._read_data", boom)
    with pytest.raises(SshManagerError, match="not shipped"):
        svc.recovery_script()                   # no raw traceback at lockout time


def test_recover_emits_tailored_snippet_with_pubkey(svc: SshManagerService) -> None:
    svc.reconcile()
    pub = (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519.pub").read_text().strip()
    snippet = svc.recovery_script("work_unc-ed25519")
    assert pub in snippet                       # the actual public key is embedded
    assert ".ssh-manager.bak" in snippet             # backs up first
    assert "chmod 600" in snippet               # fixes perms


def test_recover_unknown_or_unminted_key_errors(svc: SshManagerService) -> None:
    with pytest.raises(SshManagerError, match="public key not found"):
        svc.recovery_script("work_unc-ed25519")    # not reconciled yet


def test_recover_rejects_corrupt_pubkey(svc: SshManagerService) -> None:
    svc.reconcile()
    (svc.paths.ssh_dir / "profiles/work/work_unc-ed25519.pub").write_text("garbage\n")
    with pytest.raises(SshManagerError, match="not a valid public key"):
        svc.recovery_script("work_unc-ed25519")


def test_recover_snippet_survives_nasty_comment(svc: SshManagerService) -> None:
    import subprocess
    svc.reconcile()
    pub = svc.paths.ssh_dir / "profiles/work/work_unc-ed25519.pub"
    typ, body = pub.read_text().split()[:2]
    pub.write_text(f"{typ} {body} o'brien's laptop\n")     # single quotes in the comment
    snippet = svc.recovery_script("work_unc-ed25519")
    # the body is computed in Python (not awk $2) and embedded; the script is still valid sh
    assert f"BODY='{body}'" in snippet
    r = subprocess.run(["sh", "-n"], input=snippet, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr                     # no syntax break from the quote
