"""Security invariants: .gitignore excludes secrets; snapshots before changes."""
from __future__ import annotations

from pathlib import Path

from ssh_manager.services.facade import SshManagerService

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_gitignore_excludes_secrets() -> None:
    gi = (REPO_ROOT / ".gitignore").read_text()
    for pattern in (".env", "*.age", "config/log/", "config/snapshots/",
                    "config/.state/", "**/age-identity.txt", "**/*-identity.txt"):
        assert pattern in gi, f"missing gitignore rule: {pattern}"


def test_reconcile_snapshots_before_changing_existing_tree(svc: SshManagerService) -> None:
    svc.reconcile()                       # first run creates the tree
    res = svc.reconcile()                 # second run should snapshot the existing tree
    assert res.snapshot is not None
    assert Path(res.snapshot).exists()
    assert Path(res.snapshot).suffix == ".gz"


def test_private_keys_never_world_readable(svc: SshManagerService) -> None:
    svc.reconcile()
    for priv in svc.paths.ssh_dir.rglob("*-ed25519"):
        mode = priv.stat().st_mode & 0o077
        assert mode == 0, f"{priv} is group/other accessible"


def test_audit_log_and_state_are_owner_only(svc: SshManagerService) -> None:
    # the audit log + its dir, and the lock dir, must be owner-only the moment
    # they appear - never momentarily world-readable before a perms pass.
    svc.reconcile()                              # writes the audit log + takes the lock
    al = svc.paths.audit_log
    assert al.exists()
    assert al.stat().st_mode & 0o077 == 0, "audit.log is group/other accessible"
    assert al.parent.stat().st_mode & 0o077 == 0, "log/ is group/other accessible"
    assert svc.paths.state_dir.stat().st_mode & 0o077 == 0, ".state/ is group/other accessible"
