"""Corrupt / hostile inputs produce clean errors, never raw tracebacks - especially
on the recovery paths (restore from a backup) where it matters most."""
from __future__ import annotations

import tarfile
import types
from pathlib import Path

import pytest

from ssh_manager.core.inventory import Inventory
from ssh_manager.core.manifest import Manifest
from ssh_manager.providers.base import ProviderSpec
from ssh_manager.providers.cloud import GenericRest, Linode
from ssh_manager.providers.registry import all_specs, resolve
from ssh_manager.services.facade import SshManagerService, _host_in_known_hosts
from ssh_manager.util import fs
from ssh_manager.util.errors import ManifestError, SshManagerError
from ssh_manager.util.http import HttpError
from ssh_manager.util.log import _redact


def test_corrupt_inventory_raises_clean(tmp_path: Path) -> None:
    p = tmp_path / "inventory.json"
    p.write_text("{ corrupt")
    with pytest.raises(ManifestError, match="inventory"):
        Inventory.load(p)
    p.write_text("[1, 2, 3]")                    # valid JSON, wrong shape
    with pytest.raises(ManifestError):
        Inventory.load(p)


def test_manifest_as_directory_raises_clean(tmp_path: Path) -> None:
    """A manifest path that is a directory (hand-broken state) must surface a clean
    ManifestError, not a raw IsADirectoryError traceback."""
    p = tmp_path / "manifest.json"
    p.mkdir()
    with pytest.raises(ManifestError, match="manifest could not be read"):
        Manifest.load(p)


def test_inventory_as_directory_raises_clean(tmp_path: Path) -> None:
    """Same for the inventory: a directory at the path is a read error, not a crash.
    (The path exists, so the absent-file fast path doesn't apply.)"""
    p = tmp_path / "inventory.json"
    p.mkdir()
    with pytest.raises(ManifestError, match="inventory could not be read"):
        Inventory.load(p)


def test_host_in_known_hosts_tolerates_a_directory(tmp_path: Path) -> None:
    """If a profile's known_hosts is accidentally a directory, the membership probe
    (used by doctor + auto-pin) must return False, not crash with IsADirectoryError."""
    kh = tmp_path / "known_hosts"
    kh.mkdir()
    assert _host_in_known_hosts(kh, "github.com") is False


def test_doctor_survives_known_hosts_directory(svc: SshManagerService) -> None:
    """End-to-end: doctor walks each profile's known_hosts; a directory there must
    not take the whole command down."""
    svc.reconcile()
    kh = svc.paths.ssh_dir / "profiles" / "personal" / "known_hosts"
    kh.mkdir(parents=True, exist_ok=True)
    rep = svc.doctor()                                   # must not raise
    assert any("github.com" in h for h in rep.unpinned_hosts)   # still treated as unpinned


def test_non_dict_providers_json_does_not_crash(tmp_path: Path) -> None:
    p = tmp_path / "providers.json"
    p.write_text("[1, 2, 3]")
    assert all_specs(p)                           # falls back to built-ins, no AttributeError
    assert resolve("github", p).name == "github"  # built-in still resolves


def test_validate_unknown_selector_raises(svc: SshManagerService) -> None:
    svc.reconcile()
    with pytest.raises(SshManagerError, match="unknown key or profile"):
        svc.validate_keys("totally-bogus")


def test_restore_corrupt_snapshot_raises_clean(tmp_path: Path) -> None:
    bad = tmp_path / "ssh-bad.tar.gz"
    bad.write_bytes(b"not a gzip tar at all")
    with pytest.raises(SshManagerError, match=r"corrupt|not a valid archive"):
        fs.restore_snapshot(bad, tmp_path / ".ssh")


def test_snapshot_refuses_symlinked_ssh_dir(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "k").write_text("x")
    link = tmp_path / ".ssh"
    link.symlink_to(real)
    snaps = tmp_path / "snaps"
    with pytest.raises(SshManagerError, match="symlink"):
        fs.snapshot_ssh_dir(link, snaps)
    # a real snapshot of a real tree, then refuse to restore over a symlink
    good = fs.snapshot_ssh_dir(real, snaps, stamp="20260101-000000")
    assert good is not None and isinstance(good, Path)
    with tarfile.open(good) as archive:
        assert archive.getmembers()              # a real, readable archive
    with pytest.raises(SshManagerError, match="symlink"):
        fs.restore_snapshot(good, link)


def test_pagination_guard_fires_on_nonterminating_api() -> None:
    lin = Linode(ProviderSpec("linode", kind="linode", category="vps"))
    lin._get = types.MethodType(    # always a full page that claims more remain
        lambda self, t, u: {"data": [{"id": i, "label": "k", "ssh_key": "x"}
                                     for i in range(100)], "pages": 999}, lin)
    with pytest.raises(HttpError, match="did not terminate"):
        lin._list_keys("tok")


def test_generic_rest_requires_https() -> None:
    spec = ProviderSpec("x", kind="rest", category="vps",
                        rest={"base_url": "http://169.254.169.254", "list_field": "keys"})
    with pytest.raises(HttpError, match="https"):
        GenericRest(spec)._list_keys("tok")


def test_audit_redacts_secret_named_fields() -> None:
    out = _redact({"key": "work_x", "passphrase": "hunter2", "gh_token": "abc"})
    assert out["passphrase"] == "***" and out["gh_token"] == "***"
    assert out["key"] == "work_x"      # non-secret fields are preserved
