"""Provider integration coverage for the CLI-driven VCS adapters (gh/glab).

Two layers:
- **Recorded fixtures** (always run): feed the *real-shape* JSON that
  `gh api user/keys` / `glab api user/keys` return - including the extra fields the
  adapters must ignore - through the proc chokepoint, so field-name/shape drift in
  the parsing is caught without a network or a real account.
- **Opt-in live round-trips** (skipped unless an env flag is set): deploy a
  throwaway key to a real account, verify it, then remove it - with cleanup in a
  finally - to catch actual CLI/API drift on demand.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from ssh_manager.providers.base import Target
from ssh_manager.providers.github import GitHub
from ssh_manager.providers.gitlab import GitLab

# A body that parses as a real ed25519 wire-format key (see core.authorized_keys).
_BODY = "AAAAC3NzaC1lZDI1NTE5AAAABODY"

# Real-shape GitHub `gh api user/keys` response (extra fields MUST be ignored).
_GH_KEYS = json.dumps([
    {"id": 123456, "key": f"ssh-ed25519 {_BODY}", "title": "sshmgr work_unc-ed25519.pub",
     "url": "https://api.github.com/user/keys/123456", "created_at": "2026-01-02T03:04:05Z",
     "verified": True, "read_only": False},
])
# Real-shape GitLab `glab api user/keys` response.
_GL_KEYS = json.dumps([
    {"id": 42, "title": "sshmgr key", "key": f"ssh-ed25519 {_BODY} comment",
     "created_at": "2026-01-02T03:04:05.000Z", "expires_at": None, "usage_type": "auth"},
])


class _R:
    def __init__(self, rc: int = 0, out: str = "") -> None:
        self.returncode, self.stdout, self.stderr = rc, out, ""


def _target(tmp_path: Path, host: str) -> Target:
    pub = tmp_path / "k.pub"
    pub.write_text(f"ssh-ed25519 {_BODY} me@host\n")
    return Target(alias="x", hostname=host, user="git",
                  pubkey_path=pub, pubkey_text=pub.read_text())


def test_github_recorded_fixture_deploy_verify_remove(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GH_TOKEN", "tok")
    monkeypatch.setattr("ssh_manager.providers.github.proc.has", lambda n: True)
    deleted: list[str] = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["gh", "api"] and "--method" not in cmd:        # list
            return _R(0, _GH_KEYS)
        if "--method" in cmd:                                         # delete
            deleted.append(cmd[-1])
            return _R(0)
        return _R(0)

    monkeypatch.setattr("ssh_manager.providers.github.proc.run", fake_run)
    t = _target(tmp_path, "github.com")
    gh = GitHub()
    assert gh.deploy(t).detail == "already present"   # idempotent against the fixture
    assert gh.verify(t) is True                        # body match despite extra fields
    assert gh.remove(t) is True and deleted == ["user/keys/123456"]


def test_gitlab_recorded_fixture_deploy_verify_remove(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GLAB_TOKEN", "tok")
    monkeypatch.setattr("ssh_manager.providers.gitlab.proc.has", lambda n: True)
    deleted: list[str] = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["glab", "api"] and "--method" not in cmd:
            return _R(0, _GL_KEYS)
        if "--method" in cmd:
            deleted.append(cmd[-1])
            return _R(0)
        return _R(0)

    monkeypatch.setattr("ssh_manager.providers.gitlab.proc.run", fake_run)
    t = _target(tmp_path, "gitlab.com")
    gl = GitLab()
    assert gl.deploy(t).detail == "already present"
    assert gl.verify(t) is True
    assert gl.remove(t) is True and deleted == ["user/keys/42"]


# --- opt-in live round-trips (skipped unless explicitly enabled) -------------
@pytest.mark.skipif(not os.environ.get("SSH_MANAGER_LIVE_GITHUB"),
                    reason="set SSH_MANAGER_LIVE_GITHUB=1 (+ GH_TOKEN admin:public_key) to run")
def test_github_live_roundtrip(tmp_path) -> None:  # pragma: no cover - opt-in
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
                    "-f", str(tmp_path / "k"), "-C", "sshmgr-live-test"], check=True)
    pub = tmp_path / "k.pub"
    t = Target(alias="live", hostname="github.com", user="git",
               pubkey_path=pub, pubkey_text=pub.read_text(), identity_path=tmp_path / "k")
    gh = GitHub()
    try:
        out = gh.deploy(t)
        assert out.verified, out.detail
        assert gh.verify(t) is True
    finally:
        gh.remove(t)                       # always clean up the throwaway key
    assert gh.verify(t) is False           # gone after removal
