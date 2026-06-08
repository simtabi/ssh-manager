"""Tests for the ssh-config importer (pure parser + integration)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from ssh_manager.platforms.macos import MacOS
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.importer import parse_ssh_config

SAMPLE = """\
Host *
    AddKeysToAgent yes

Host unc
    HostName sc.its.unc.edu
    User uncgit
    Port 443
    IdentityFile ~/.ssh/profiles/work/work_unc-ed25519

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
"""


RAW = """\
Host unc
    HostName sc.its.unc.edu
    User uncgit
    Port 443
    ProxyJump bastion.unc.edu
    PreferredAuthentications publickey
    IdentityFile ~/.ssh/profiles/work/work_unc-ed25519
"""


def test_import_carries_raw_options_and_infers_provider(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    cfg = home / ".ssh" / "config"
    cfg.write_text(RAW + "\nHost gh\n    HostName github.com\n    User git\n")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    svc = SshManagerService(
        env={"SSH_MANAGER_CONFIG_DIR": str(config_dir)}, ssh_dir=home / ".ssh", platform=MacOS(),
    )
    svc.import_ssh(cfg)
    unc = svc.manifest().profiles["work"].hosts[0]
    assert unc.raw_options.get("proxyjump") == "bastion.unc.edu"   # passthrough, not dropped
    gh = svc.manifest().profiles["imported"].hosts[0]
    assert gh.provider == "github"                                  # inferred from hostname


def test_import_dedupes_duplicate_aliases(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    cfg = home / ".ssh" / "config"
    cfg.write_text(                                  # two Host gh blocks (weird input)
        "Host gh\n    HostName github.com\n    User git\n"
        "Host gh\n    HostName github.com\n    User other\n")
    svc = SshManagerService(env={"SSH_MANAGER_CONFIG_DIR": str(tmp_path / "cfg")},
                        ssh_dir=home / ".ssh", platform=MacOS())
    svc.import_ssh(cfg)
    hosts = svc.manifest().profiles["imported"].hosts
    assert [h.alias for h in hosts] == ["gh"]        # collapsed to one, first wins
    assert hosts[0].user == "git"


def test_parser_skips_wildcards_and_reads_fields() -> None:
    hosts = parse_ssh_config(SAMPLE)
    aliases = [h.alias for h in hosts]
    assert aliases == ["unc", "github.com"]      # Host * skipped
    unc = hosts[0]
    assert unc.hostname == "sc.its.unc.edu"
    assert unc.user == "uncgit"
    assert unc.port == 443
    assert unc.profile == "work"                  # derived from IdentityFile path
    assert hosts[1].profile == "imported"         # id_ed25519 not under profiles/


def test_import_writes_manifest(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    cfg = home / ".ssh" / "config"
    cfg.write_text(SAMPLE)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    svc = SshManagerService(
        env={"SSH_MANAGER_CONFIG_DIR": str(config_dir)},
        ssh_dir=home / ".ssh",
        platform=MacOS(),
    )
    res = svc.import_ssh(cfg)
    assert res.profiles == {"work": 1, "imported": 1}
    manifest = svc.manifest()
    assert manifest.profiles["work"].hosts[0].port == 443


def test_import_adopts_non_canonical_key_no_phantom_mint(tmp_path, monkeypatch) -> None:
    """A key at ~/.ssh/id_ed25519 must be ADOPTED into the profiles/ layout, and a
    subsequent reconcile must NOT mint a phantom key shadowing it (regression C1)."""
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    # a real existing key outside the profiles/ layout
    src = ssh / "id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(src), "-N", "", "-q"], check=True)
    fp_before = subprocess.run(
        ["ssh-keygen", "-lf", str(src)], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    (ssh / "config").write_text(
        "Host github.com\n    HostName github.com\n    User git\n"
        f"    IdentityFile {src}\n"
    )
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    svc = SshManagerService(
        env={"SSH_MANAGER_CONFIG_DIR": str(config_dir)}, ssh_dir=ssh, platform=MacOS(),
    )
    res = svc.import_ssh(ssh / "config")
    assert res.adopted == 1
    adopted = ssh / "profiles/imported/imported_github-com-ed25519"
    assert adopted.exists() and adopted.with_suffix(".pub").exists()
    # the rendered IdentityFile points exactly where the adopted key lives
    manifest = svc.manifest()
    host = manifest.profiles["imported"].hosts[0]
    assert manifest.identity_file("imported", host.key_name) == \
        "~/.ssh/profiles/imported/imported_github-com-ed25519"
    # reconcile mints NOTHING for this host (the adopted key is already present)
    rec = svc.reconcile()
    assert all("imported" not in m.profile or m.fingerprint == fp_before for m in rec.minted)
    assert not any(m.key_name == "imported_github-com-ed25519" for m in rec.minted)
    # same fingerprint preserved (true adoption, not a new keypair)
    fp_after = subprocess.run(
        ["ssh-keygen", "-lf", str(adopted)], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    assert fp_after == fp_before
