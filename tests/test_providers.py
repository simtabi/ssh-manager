"""Config-driven providers: all VCS (cloud + enterprise/self-hosted)"""
from __future__ import annotations

from pathlib import Path

from ssh_manager.providers.base import ProviderSpec, Target, keys_url_for
from ssh_manager.providers.github import GitHub
from ssh_manager.providers.gitlab import GitLab
from ssh_manager.providers.registry import resolve
from ssh_manager.providers.ssh_generic import GenericSSH

PROVIDERS = Path(__file__).resolve().parent.parent / "config" / "providers.json"


def _target(tmp_path: Path) -> Target:
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAABLOB comment")
    return Target(alias="x", hostname="h", user="git",
                  pubkey_path=pub, pubkey_text=pub.read_text())


def test_every_committed_provider_resolves() -> None:
    import json
    names = json.loads(PROVIDERS.read_text())["providers"].keys()
    for name in names:
        p = resolve(name, PROVIDERS)
        assert p.category in {"vcs", "panel", "server", "generic", "vps"}


def test_github_cloud_vs_enterprise(monkeypatch, tmp_path: Path) -> None:
    cloud = resolve("github", PROVIDERS)
    ghe = resolve("github-enterprise", PROVIDERS)
    assert isinstance(cloud, GitHub) and isinstance(ghe, GitHub)
    assert not cloud._is_enterprise() and ghe._is_enterprise()
    # gh selects the instance + credential via env vars, not a (nonexistent) flag.
    monkeypatch.setenv("GH_TOKEN", "cloud-tok")
    monkeypatch.setenv("GHE_TOKEN", "ghe-tok")
    t = _target(tmp_path)
    assert cloud._env(t) == {"GH_HOST": "github.com", "GH_TOKEN": "cloud-tok"}
    assert ghe._env(t) == {"GH_HOST": "github.example.com",
                           "GH_ENTERPRISE_TOKEN": "ghe-tok"}
    assert cloud.manage_url(t) == "https://github.com/settings/keys"
    assert ghe.manage_url(t) == "https://github.example.com/settings/keys"


def test_gitlab_self_hosted_uses_host(monkeypatch, tmp_path: Path) -> None:
    gl = resolve("gitlab-self-hosted", PROVIDERS)
    assert isinstance(gl, GitLab)
    monkeypatch.setenv("GLAB_TOKEN", "gl-tok")
    # glab targets the instance + auth via GITLAB_HOST / GITLAB_TOKEN env vars.
    assert gl._env(_target(tmp_path)) == {"GITLAB_TOKEN": "gl-tok",
                                          "GITLAB_HOST": "gitlab.example.com"}


def test_all_vcs_have_a_manual_keys_url(tmp_path: Path) -> None:
    t = _target(tmp_path)
    for name in ["bitbucket", "bitbucket-server", "gitea", "codeberg", "forgejo",
                 "gogs", "sourcehut", "azure-devops", "aws-codecommit"]:
        p = resolve(name, PROVIDERS)
        assert p.category == "vcs"
        out = p.deploy(t)                  # no CLI -> universal manual path
        assert out.method == "manual"
        assert p.manage_url(t) is not None  # always points somewhere to paste the key


def test_unknown_provider_falls_back_to_generic_ssh() -> None:
    assert isinstance(resolve("totally-unknown", PROVIDERS), GenericSSH)
    assert isinstance(resolve(None, PROVIDERS), GenericSSH)


def test_catalog_falls_back_to_shipped_default_when_user_file_absent(tmp_path) -> None:
    # No user providers.json -> resolution uses the shipped package catalog, which
    # includes names NOT in the minimal built-in specs (e.g. bitbucket).
    from ssh_manager.providers.registry import all_specs
    missing = tmp_path / "providers.json"
    assert not missing.exists()
    p = resolve("bitbucket", missing)
    assert p.category == "vcs"                       # from shipped catalog, not generic-ssh
    assert {"bitbucket", "gitea", "scaleway"} <= set(all_specs(missing))


def test_keys_url_derivation() -> None:
    assert keys_url_for("github", "ghe.corp") == "https://ghe.corp/settings/keys"
    assert keys_url_for("gitea", None) == "https://gitea.com/user/settings/keys"
    assert keys_url_for("aws-codecommit", None).startswith("https://console.aws.amazon.com")
    assert keys_url_for("unknown-kind", "x.io") == "https://x.io"


def test_spec_token_env_used_by_github(monkeypatch, tmp_path: Path) -> None:
    spec = ProviderSpec("ghe", kind="github", category="vcs",
                        host="ghe.corp", token_env="GHE_TOKEN")
    gh = GitHub(spec)
    monkeypatch.setenv("GHE_TOKEN", "secret")
    assert gh._token(_target(tmp_path)) == "secret"
