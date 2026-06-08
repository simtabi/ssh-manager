"""Shared fixtures: a sandboxed SshManagerService over a temp HOME + config-dir.

Tests force the macOS platform (the first-class v1 target) so UseKeychain and
perms behaviour are deterministic regardless of the CI OS.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ssh_manager.core.manifest import Defaults, Host, Manifest, Profile
from ssh_manager.platforms.macos import MacOS
from ssh_manager.services.facade import SshManagerService

GLOBAL_OPTS = {
    "AddKeysToAgent": "yes",
    "IgnoreUnknown": "UseKeychain",
    "UseKeychain": "yes",
    "IdentitiesOnly": "yes",
    "ServerAliveInterval": "60",
}


def sample_manifest() -> Manifest:
    return Manifest(
        defaults=Defaults(global_options=dict(GLOBAL_OPTS)),
        profiles={
            "work": Profile(hosts=[
                Host(alias="unc", hostname="sc.its.unc.edu", user="uncgit",
                     port=443, key_name="work_unc-ed25519",
                     requires_vpn=True, vpn_name="UNC VPN",
                     vpn_url="https://vpn.unc.edu"),
            ]),
            # NOTE: personal deliberately uses the bare hostname as the alias to
            # exercise the unprefixed path; the shipped example (config/manifest.json)
            # and docs use the recommended prefixed form (github-personal).
            "personal": Profile(hosts=[
                Host(alias="github.com", hostname="github.com", user="git",
                     provider="github", key_name="personal_github-ed25519"),
            ]),
            "simtabi": Profile(hosts=[
                Host(alias="github-simtabi", hostname="github.com", user="git",
                     provider="github", token_env="GH_TOKEN_SIMTABI",
                     key_name="simtabi_github-ed25519"),
            ]),
            "development": Profile(hosts=[
                Host(alias="oribi-web", hostname="143.198.186.131", user="ploi",
                     provider="ploi", key_name="development_oribi-web-ed25519",
                     tags=["app"],
                     raw_options={"PreferredAuthentications": "publickey"}),
            ]),
            "shared-demo": Profile(key_scope="shared", key_name="shareddemo_all-ed25519",
                                   hosts=[
                Host(alias="box-a", hostname="10.0.0.1", user="root"),
                Host(alias="box-b", hostname="10.0.0.2", user="root"),
            ]),
            "school": Profile(hosts=[]),
        },
    )


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    # Keep the suite offline + deterministic: reconcile/keygen auto-pin host keys via
    # ssh-keyscan by default; disable it here. Tests that exercise auto-pin opt back in.
    monkeypatch.setenv("SSH_MANAGER_AUTO_PIN", "0")
    sample_manifest().save(config_dir / "manifest.json")
    return {"home": home, "ssh_dir": ssh_dir, "config_dir": config_dir}


@pytest.fixture
def svc(env: dict[str, Path]) -> SshManagerService:
    return SshManagerService(
        env={"SSH_MANAGER_CONFIG_DIR": str(env["config_dir"])},
        ssh_dir=env["ssh_dir"],
        platform=MacOS(),
    )
