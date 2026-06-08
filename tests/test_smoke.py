"""Smoke tests that run without external deps installed beyond pydantic."""
from ssh_manager import __version__
from ssh_manager.core.key import build_key_name, normalize_segment, split_key_name


def test_version():
    assert isinstance(__version__, str) and __version__


def test_key_name_convention():
    assert build_key_name("development", "oribi-db-psql") == "development_oribi-db-psql-ed25519"
    assert build_key_name("work", "UNC") == "work_unc-ed25519"
    assert build_key_name("simtabi", "github", "ed25519-sk") == "simtabi_github-ed25519-sk"


def test_normalize_and_split():
    assert normalize_segment("sc.its.unc.edu") == "sc-its-unc-edu"
    assert split_key_name("development_oribi-web-ed25519") == ("development", "oribi-web-ed25519")
