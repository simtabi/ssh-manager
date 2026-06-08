"""known_hosts pinning via ssh-keyscan - scan/fingerprint/add."""
from __future__ import annotations

import stat
from pathlib import Path

from ssh_manager.platforms.macos import MacOS
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.knownhosts import KnownHostsService

SCAN = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTBLOB\n"


def test_scan_fingerprints_and_add_dedupes(tmp_path: Path, monkeypatch) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()

    def fake_run(cmd, **kw):
        class R:
            returncode = 0
            stderr = ""
            stdout = SCAN if cmd[0] == "ssh-keyscan" else "256 SHA256:abc123 example.com (ED25519)"
        return R()

    monkeypatch.setattr("ssh_manager.services.knownhosts.proc.has", lambda b: True)
    monkeypatch.setattr("ssh_manager.services.knownhosts.proc.run", fake_run)
    svc = KnownHostsService(MacOS(), ssh)

    scanned = svc.scan("example.com")
    assert len(scanned) == 1
    assert scanned[0].keytype == "ssh-ed25519"
    assert scanned[0].fingerprint == "SHA256:abc123"

    # writes to the per-profile store (everything under profiles/)
    assert svc.add([scanned[0].line], "work") == 1   # first add writes it
    assert svc.add([scanned[0].line], "work") == 0   # idempotent - already present
    kh = svc.path_for("work")
    assert kh == ssh / "profiles/work/known_hosts"
    assert stat.S_IMODE(kh.stat().st_mode) == 0o644
    assert "example.com" in kh.read_text()


def test_facade_targets_and_add_per_profile(svc: SshManagerService) -> None:
    targets = svc.known_hosts_targets()
    pairs = {(prof, hn) for prof, _a, hn, _p in targets}
    assert ("work", "sc.its.unc.edu") in pairs
    assert ("personal", "github.com") in pairs and ("simtabi", "github.com") in pairs
    assert svc.profile_of_alias("unc") == "work"
    n = svc.known_hosts_add(["h ssh-ed25519 AAAABLOB"], "work")
    assert n == 1
    assert (svc.paths.ssh_dir / "profiles/work/known_hosts").exists()   # under the profile
