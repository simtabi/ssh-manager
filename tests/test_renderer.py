"""Unit tests for the single renderer (invariant 3,)."""
from __future__ import annotations

from ssh_manager.core.renderer import (
    MANAGED_END,
    MANAGED_HEADER,
    compose_root_config,
    render_all,
    render_root_config,
)
from tests.conftest import sample_manifest

_ORB = (
    "# Added by OrbStack: 'orb' SSH host for Linux machines\n"
    "# This won't be added again if you remove it.\n"
    "Include ~/.orbstack/ssh/config\n"
)


def _managed() -> str:
    return render_root_config({"AddKeysToAgent": "yes"}, emit_use_keychain=False)


def test_root_config_managed_header_and_order() -> None:
    out = render_all(sample_manifest(), emit_use_keychain=True)
    root = out["config"]
    assert root.startswith(MANAGED_HEADER + "\n")
    assert "Include profiles/*/config" in root
    # IgnoreUnknown must precede the UseKeychain it guards.
    assert root.index("IgnoreUnknown UseKeychain") < root.index("UseKeychain yes")


def test_use_keychain_dropped_off_macos() -> None:
    on = render_all(sample_manifest(), emit_use_keychain=True)["config"]
    off = render_all(sample_manifest(), emit_use_keychain=False)["config"]
    assert "UseKeychain yes" in on
    assert "UseKeychain yes" not in off
    # IgnoreUnknown line is harmless and stays for portability.
    assert "IgnoreUnknown UseKeychain" in off


def test_empty_profile_renders_no_file() -> None:
    out = render_all(sample_manifest(), emit_use_keychain=True)
    assert "profiles/school/config" not in out


def test_port_emitted_only_when_non_default() -> None:
    out = render_all(sample_manifest(), emit_use_keychain=True)
    assert "Port 443" in out["profiles/work/config"]
    assert "Port" not in out["profiles/personal/config"]


def test_raw_options_passthrough() -> None:
    dev = render_all(sample_manifest(), emit_use_keychain=True)["profiles/development/config"]
    assert "PreferredAuthentications publickey" in dev


def test_per_profile_known_hosts_isolation() -> None:
    """Each host points at its OWN profile's known_hosts - host-key trust never
    bleeds across identity contexts (everything lives under the profile)."""
    out = render_all(sample_manifest(), emit_use_keychain=True)
    assert "UserKnownHostsFile ~/.ssh/profiles/work/known_hosts" in out["profiles/work/config"]
    personal = out["profiles/personal/config"]
    simtabi = out["profiles/simtabi/config"]
    assert "UserKnownHostsFile ~/.ssh/profiles/personal/known_hosts" in personal
    assert "UserKnownHostsFile ~/.ssh/profiles/simtabi/known_hosts" in simtabi
    # same real github.com host, but DISTINCT trust stores per identity
    assert "profiles/simtabi/known_hosts" not in personal


def test_two_github_identities_are_distinct() -> None:
    out = render_all(sample_manifest(), emit_use_keychain=True)
    personal = out["profiles/personal/config"]
    simtabi = out["profiles/simtabi/config"]
    assert "Host github.com" in personal
    assert "Host github-simtabi" in simtabi
    # Same real HostName, distinct alias + distinct IdentityFile (no cross-offer).
    assert "HostName github.com" in personal and "HostName github.com" in simtabi
    assert "personal/personal_github-ed25519" in personal
    assert "simtabi/simtabi_github-ed25519" in simtabi
    assert "simtabi_github" not in personal


def test_shared_scope_points_all_hosts_at_one_key() -> None:
    out = render_all(sample_manifest(), emit_use_keychain=True)
    cfg = out["profiles/shared-demo/config"]
    assert cfg.count("shareddemo_all-ed25519") == 2  # both hosts -> one key


# --- foreign-content preservation in the root config ------------------------
def test_root_block_is_delimited_by_end_marker() -> None:
    root = render_all(sample_manifest(), emit_use_keychain=True)["config"]
    assert root.startswith(MANAGED_HEADER + "\n")
    assert root.rstrip().endswith(MANAGED_END)


def test_compose_preserves_orbstack_preamble_at_top() -> None:
    composed = compose_root_config(_ORB, _managed())
    assert composed.startswith("# Added by OrbStack")        # stays at the very top
    assert "Include ~/.orbstack/ssh/config" in composed
    assert MANAGED_HEADER in composed and MANAGED_END in composed
    # OrbStack's Include precedes ssh-manager's managed block (and its Host *)
    assert composed.index("orbstack/ssh/config") < composed.index("Include profiles/*/config")


def test_compose_is_idempotent_and_preserves_trailer() -> None:
    composed = compose_root_config(_ORB, _managed())
    assert compose_root_config(composed, _managed()) == composed
    with_trailer = composed + "\n# hand-added footer\nHost legacy\n  HostName 1.2.3.4\n"
    again = compose_root_config(with_trailer, _managed())
    assert "# hand-added footer" in again and "Host legacy" in again
    assert again.startswith("# Added by OrbStack")
    assert compose_root_config(again, _managed()) == again


def test_compose_fresh_is_managed_only() -> None:
    assert compose_root_config(None, _managed()) == _managed()
    assert compose_root_config("", _managed()) == _managed()


def test_compose_migrates_old_format_without_end_marker() -> None:
    old = _ORB + MANAGED_HEADER + "\nInclude profiles/*/config\nHost *\n    OldOpt yes\n"
    migrated = compose_root_config(old, _managed())
    assert migrated.startswith("# Added by OrbStack")        # preamble kept
    assert MANAGED_END in migrated and "OldOpt" not in migrated   # block replaced
    assert compose_root_config(migrated, _managed()) == migrated
