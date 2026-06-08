"""Unit tests for manifest models + key resolution."""
from __future__ import annotations

from pathlib import Path

import pytest

from ssh_manager.core.inventory import compute_expiry
from ssh_manager.core.key import algo_of, derive_key_name
from ssh_manager.core.manifest import Host, Manifest, Profile
from ssh_manager.util.errors import ManifestError
from tests.conftest import sample_manifest


def test_load_save_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "manifest.json"
    sample_manifest().save(p)
    again = Manifest.load(p)
    assert again.profiles["work"].hosts[0].port == 443


def test_load_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        Manifest.load(tmp_path / "nope.json")


def test_load_rejects_unknown_field(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text('{"version": 1, "profiles": {"x": {"bogus": 1, "hosts": []}}}')
    with pytest.raises(ManifestError):
        Manifest.load(p)


def test_resolved_key_name_per_service_default() -> None:
    m = Manifest(profiles={"work": Profile(hosts=[
        Host(alias="sc.its.unc.edu", hostname="sc.its.unc.edu", user="uncgit"),
    ])})
    host = m.profiles["work"].hosts[0]
    assert m.resolved_key_name("work", host) == "work_sc-its-unc-edu-ed25519"


def test_resolved_key_name_shared() -> None:
    m = sample_manifest()
    host = m.profiles["shared-demo"].hosts[0]
    assert m.resolved_key_name("shared-demo", host) == "shareddemo_all-ed25519"


def test_shared_without_key_name_raises() -> None:
    m = Manifest(profiles={"p": Profile(key_scope="shared", hosts=[
        Host(alias="a", hostname="a", user="u"),
    ])})
    with pytest.raises(ManifestError):
        m.resolved_key_name("p", m.profiles["p"].hosts[0])


def test_derive_and_algo() -> None:
    assert derive_key_name("development", "oribi-db-psql") == "development_oribi-db-psql-ed25519"
    assert algo_of("simtabi_github-ed25519-sk") == "ed25519-sk"
    assert algo_of("work_unc-ed25519") == "ed25519"


def test_compute_expiry() -> None:
    assert compute_expiry("2026-06-03", 365) == "2027-06-03"
