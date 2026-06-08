"""Regression tests for the audit-driven fixes (providers env, shared-key delete,
deploy exit semantics, manifest hardening, import guard, importer parsing,
rotation inventory dedup)."""
from __future__ import annotations

import json

import pytest

from ssh_manager.core.manifest import Host, Manifest, Profile
from ssh_manager.providers.base import DeployOutcome, Target
from ssh_manager.providers.github import GitHub
from ssh_manager.providers.ssh_generic import GenericSSH
from ssh_manager.services.facade import SshManagerService
from ssh_manager.services.importer import parse_ssh_config
from ssh_manager.util import fs
from ssh_manager.util.errors import ManifestError, SshManagerError


# --- manifest hardening -----------------------------------------------------
def test_manifest_rejects_code_executing_options() -> None:
    for opt in ("KnownHostsCommand", "PKCS11Provider", "SecurityKeyProvider"):
        with pytest.raises(ValueError, match="not allowed"):
            Host(alias="a", hostname="h", user="u", raw_options={opt: "/tmp/x"})


def test_manifest_rejects_whitespace_and_glob_names() -> None:
    with pytest.raises(ValueError):
        Host(alias="my box", hostname="h", user="u")          # whitespace alias
    with pytest.raises(ValueError):
        Host(alias="*", hostname="h", user="u")               # wildcard alias
    with pytest.raises(ValueError):
        Host(alias="a", hostname="h h", user="u")             # whitespace hostname


# --- shared-key delete ------------------------------------------------------
def test_shared_key_delete_keeps_record_for_remaining_host(
        svc: SshManagerService, monkeypatch) -> None:
    revoked: list[str] = []
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr(GenericSSH, "verify", lambda self, t: True)
    monkeypatch.setattr(GenericSSH, "remove",
                        lambda self, t: revoked.append(t.alias) or True)
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    svc.reconcile()
    svc.deploy("shareddemo_all-ed25519")           # deployed to box-a AND box-b
    # delete box-a, revoke it from its own target; box-b still uses the key
    res = svc.host_delete("shared-demo", "box-a", revoke=True)
    assert res.revoked == ["box-a"]
    inv = svc.inventory()
    # the shared key record SURVIVES (box-b still uses it) and box-b's deployment stays
    recs = [r for r in inv.keys.values() if r.path.endswith("shareddemo_all-ed25519")]
    assert recs, "shared key record must survive while box-b still uses it"
    targets = {d.target for r in recs for d in r.deployments}
    assert "box-b" in targets and "box-a" not in targets


def test_profile_delete_revokes_all_shared_hosts(svc: SshManagerService, monkeypatch) -> None:
    revoked: list[str] = []
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr(GenericSSH, "verify", lambda self, t: True)
    monkeypatch.setattr(GenericSSH, "remove",
                        lambda self, t: revoked.append(t.alias) or True)
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    svc.reconcile()
    svc.deploy("shareddemo_all-ed25519")
    res = svc.profile_delete("shared-demo", revoke=True)
    # BOTH hosts get revoked (the old code skipped box-b after pruning on box-a)
    assert set(res.revoked) == {"box-a", "box-b"}
    assert "shared-demo" not in svc.manifest().profiles


# --- deploy error semantics -------------------------------------------------
def test_deploy_marks_failed_provider_as_error(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr(GenericSSH, "deploy", lambda self, t: DeployOutcome(
        "ssh-copy-id", verified=False, detail="boom", error=True))
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    svc.reconcile()
    report = svc.deploy("shareddemo_all-ed25519")
    assert all(r.error for r in report.records)        # CLI exits non-zero on these


def test_manual_target_is_not_an_error(svc: SshManagerService) -> None:
    svc.reconcile()
    # development/oribi-web uses ploi -> manual deploy; needs a paste, NOT an error.
    report = svc.deploy("development_oribi-web-ed25519")
    assert report.records and not any(r.error for r in report.records)


# --- github adapter (env-based host/cred selection, body-matched removal) ---
def test_github_remove_matches_by_body(monkeypatch, tmp_path) -> None:
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY new@host\n")
    gh = GitHub()
    monkeypatch.setenv("GH_TOKEN", "tok")
    deleted: list[str] = []

    class R:
        def __init__(self, rc, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def fake_run(cmd, **kw):
        if cmd[:2] == ["gh", "api"] and "--method" not in cmd:    # list
            return R(0, json.dumps([
                {"id": 1, "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY x", "title": "a"},
                {"id": 2, "key": "ssh-ed25519 DIFFERENTBODY y", "title": "b"},
            ]))
        if "--method" in cmd:                                     # delete by id
            deleted.append(cmd[-1])
            return R(0)
        return R(0)

    monkeypatch.setattr("ssh_manager.providers.github.proc.run", fake_run)
    monkeypatch.setattr("ssh_manager.providers.github.proc.has", lambda n: True)
    t = Target(alias="x", hostname="github.com", user="git",
               pubkey_path=pub, pubkey_text=pub.read_text())
    assert gh.remove(t) is True
    assert deleted == ["user/keys/1"]          # only the body-matching key deleted


# --- import guard -----------------------------------------------------------
def test_import_refuses_to_clobber_nonempty_manifest(svc: SshManagerService, tmp_path) -> None:
    cfg = tmp_path / "ssh_config"
    cfg.write_text("Host h1\n  HostName 1.2.3.4\n  User bob\n")
    with pytest.raises(SshManagerError, match="non-empty manifest already exists"):
        svc.import_ssh(cfg)                    # the fixture manifest has profiles


def test_import_force_backs_up_then_replaces(svc: SshManagerService, tmp_path) -> None:
    cfg = tmp_path / "ssh_config"
    cfg.write_text("Host h1\n  HostName 1.2.3.4\n  User bob\n")
    svc.import_ssh(cfg, force=True)
    # old manifest backed up under <home>/.state/import-backup-*
    backups = list(svc.paths.state_dir.glob("import-backup-*/manifest.json"))
    assert backups, "force-import must back up the previous manifest"
    assert "h1" in {h.alias for p in svc.manifest().profiles.values() for h in p.hosts}


def test_import_directory_path_is_clean_error(svc: SshManagerService, tmp_path) -> None:
    # force past the non-empty-manifest guard so we reach the importer's file read
    with pytest.raises(ManifestError, match="no ssh config file"):
        svc.import_ssh(tmp_path, force=True)   # a directory, not a file


# --- importer parsing -------------------------------------------------------
def test_parse_multi_alias_applies_to_all() -> None:
    hosts = parse_ssh_config("Host web1 web2\n  HostName 10.0.0.5\n  User deploy\n")
    assert {h.alias for h in hosts} == {"web1", "web2"}
    assert all(h.hostname == "10.0.0.5" and h.user == "deploy" for h in hosts)


def test_parse_match_block_terminates_and_dangerous_dropped() -> None:
    text = (
        "Host real\n  HostName 1.2.3.4\n  ProxyCommand /bin/evil\n"
        "Match host *.corp\n  User leak\n"
    )
    hosts = parse_ssh_config(text)
    real = next(h for h in hosts if h.alias == "real")
    assert "proxycommand" not in real.extra          # code-executing option dropped
    assert real.user == ""                            # Match body did not leak in
    # and the parsed host builds a valid manifest (no validation abort)
    Manifest(profiles={"imported": Profile(hosts=[
        Host(alias=real.alias, hostname=real.hostname or real.alias,
             user=real.user or "git")])})


# --- rotation inventory dedup ----------------------------------------------
def test_double_rotate_keeps_single_old_inventory_record(
        svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr(GenericSSH, "verify", lambda self, t: True)
    monkeypatch.setattr(GenericSSH, "remove", lambda self, t: True)
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    svc.reconcile()
    key = "work_unc-ed25519"
    svc.rotate(key)
    svc.rotate(key)
    inv = svc.inventory()
    old_records = [r for r in inv.keys.values() if "/old/" in r.path
                   and r.path.endswith(key)]
    assert len(old_records) == 1               # exactly one archived predecessor record


# --- snapshot ordering (same-second collision) ------------------------------
def test_snapshot_latest_is_newest_on_same_second(tmp_path) -> None:
    import os
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    # Same-second names: base + collision suffixes (as _unique_path produces).
    base = snaps / "ssh-20260101-000000.tar.gz"      # created first (oldest)
    c1 = snaps / "ssh-20260101-000000-1.tar.gz"
    c2 = snaps / "ssh-20260101-000000-2.tar.gz"      # created last (newest)
    for p in (base, c1, c2):
        p.write_bytes(b"x")
    # stamp mtimes in true creation order (sub-second apart)
    os.utime(base, ns=(1_000_000_000, 1_000_000_000))
    os.utime(c1, ns=(1_000_000_001, 1_000_000_001))
    os.utime(c2, ns=(1_000_000_002, 1_000_000_002))
    ordered = fs.list_snapshots(snaps)
    assert ordered[-1] == c2 and ordered[0] == base   # newest last, oldest first


# --- foreign config preservation (OrbStack etc.) ---------------------------
def test_reconcile_preserves_orbstack_preamble(svc: SshManagerService) -> None:
    cfg = svc.paths.ssh_dir / "config"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    # An OrbStack-style preamble exists BEFORE sshmgr has ever written the config.
    cfg.write_text(
        "# Added by OrbStack: 'orb' SSH host for Linux machines\n"
        "# This won't be added again if you remove it.\n"
        "Include ~/.orbstack/ssh/config\n")
    svc.reconcile()                                   # mints keys + writes config
    text = cfg.read_text()
    assert text.startswith("# Added by OrbStack")     # preamble survived at the top
    assert "Include ~/.orbstack/ssh/config" in text
    assert "Include profiles/*/config" in text        # sshmgr block added below it
    # config check must NOT flag the preserved preamble as drift
    assert svc.config_check().in_sync
    # re-rendering is idempotent and still preserves the preamble
    res = svc.config_render()
    assert "config" not in res.written                # unchanged
    assert cfg.read_text().startswith("# Added by OrbStack")


# --- auto-pin known_hosts on reconcile/keygen ------------------------------
def test_reconcile_auto_pins_each_profile_known_hosts(svc: SshManagerService, monkeypatch) -> None:
    from ssh_manager.services.knownhosts import ScannedKey
    monkeypatch.setenv("SSH_MANAGER_AUTO_PIN", "1")              # opt back in (conftest disables)
    monkeypatch.setattr("ssh_manager.services.facade.proc.has", lambda n: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)

    def fake_scan(self, host, port=22):
        tok = host if port == 22 else f"[{host}]:{port}"   # ssh-keyscan's non-22 form
        return [ScannedKey(host, port, "ssh-ed25519",
                           f"{tok} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY", "SHA256:x")]

    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", fake_scan)
    res = svc.reconcile()
    # every profile with hosts got its known_hosts created + populated
    for prof in ("work", "personal", "simtabi", "development"):
        kh = svc.paths.ssh_dir / "profiles" / prof / "known_hosts"
        assert kh.exists() and kh.read_text().strip(), f"{prof} known_hosts not pinned"
    assert res.pinned and sum(res.pinned.values()) >= 4
    # doctor now sees them as pinned (no unpinned warning)
    assert not svc.doctor().unpinned_hosts
    # idempotent: a second reconcile pins nothing new (already trusted, never overridden)
    assert svc.reconcile().pinned == {}


def test_auto_pin_disabled_by_env(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setenv("SSH_MANAGER_AUTO_PIN", "0")
    called = {"scan": False}
    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan",
                        lambda self, h, p=22: called.__setitem__("scan", True) or [])
    res = svc.reconcile()
    assert res.pinned == {} and called["scan"] is False     # never touched the network


# --- doctor surfaces unpinned host keys ------------------------------------
def test_doctor_flags_unpinned_host_keys(svc: SshManagerService) -> None:
    svc.reconcile()                                    # mints keys; no known_hosts pinned
    rep = svc.doctor()
    # every manifest host is unpinned -> flagged with its alias
    aliases = " ".join(rep.unpinned_hosts)
    assert "github.com" in aliases and "unc" in aliases
    assert "knownhosts pin" in rep.format()            # remedy is shown
    # pin the personal github host key -> that alias drops off the unpinned list
    kh = svc.paths.ssh_dir / "profiles" / "personal" / "known_hosts"
    kh.write_text("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY\n")
    rep2 = svc.doctor()
    personal = [h for h in rep2.unpinned_hosts if h.startswith("github.com ")]
    assert not personal                                # personal github now pinned
    # a non-22 host uses the [host]:port token form
    assert any("unc" in h for h in rep2.unpinned_hosts)  # unc (port 443) still unpinned


# --- per-profile known_hosts used by deploy/verify (isolation, not default store) -
def test_ssh_provider_uses_per_profile_known_hosts(tmp_path, monkeypatch) -> None:
    cap: dict[str, list[str]] = {}

    class R:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr("ssh_manager.providers.ssh_generic.proc.run",
                        lambda cmd, **k: cap.__setitem__("cmd", cmd) or R())
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY x")
    priv = tmp_path / "k"
    priv.write_text("x")
    kh = tmp_path / "profiles" / "work" / "known_hosts"
    t = Target(alias="a", hostname="h", user="u", pubkey_path=pub, pubkey_text=pub.read_text(),
               identity_path=priv, known_hosts=kh)
    GenericSSH().verify(t)
    # verify must read+populate the host's OWN per-profile store, not ~/.ssh/known_hosts
    assert f"UserKnownHostsFile={kh}" in cap["cmd"]


def test_deployer_threads_per_profile_known_hosts(svc: SshManagerService, monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(GenericSSH, "deploy",
                        lambda self, t: captured.__setitem__("kh", t.known_hosts)
                        or DeployOutcome("ssh-copy-id", True))
    monkeypatch.setattr("ssh_manager.util.net.ssh_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    svc.reconcile()
    svc.deploy("shareddemo_all-ed25519", "box-a")
    assert str(captured["kh"]).endswith("profiles/shared-demo/known_hosts")


# --- providers export + catalog fallback ------------------------------------
def test_providers_export_materializes_catalog(svc: SshManagerService) -> None:
    dest = svc.paths.providers
    assert not dest.exists()                       # init does not seed it
    assert svc.providers_source() == "shipped default"
    out = svc.export_providers()
    assert out == dest and dest.exists()
    import json
    assert "providers" in json.loads(dest.read_text())   # real catalog written
    assert svc.providers_source() == "user file"
    # refuses to clobber without force; --force overwrites
    with pytest.raises(SshManagerError, match="already exists"):
        svc.export_providers()
    svc.export_providers(force=True)               # ok


def test_doctor_reports_providers_source_and_stranded_legacy(svc: SshManagerService) -> None:
    rep = svc.doctor()
    assert rep.providers_source == "shipped default"   # no user file in the sandbox
    assert rep.stranded_legacy_home is None            # HOME is the temp sandbox


def test_doctor_as_dict_is_json_serializable(svc: SshManagerService) -> None:
    import json
    svc.reconcile()
    d = svc.doctor().as_dict()
    json.dumps(d)                                      # must not raise
    assert {"ok", "home", "providers_source", "unpinned_hosts"} <= set(d)
    assert isinstance(d["ok"], bool)


def test_resolve_secret_plain_and_cmd_indirection(monkeypatch) -> None:
    from ssh_manager.util.secrets import resolve_secret
    assert resolve_secret("plaintok") == "plaintok"   # plain value passes through
    assert resolve_secret(None) is None
    assert resolve_secret("") is None
    assert resolve_secret("cmd:echo s3cret") == "s3cret"   # runs cmd, trims stdout
    assert resolve_secret("cmd:false") is None             # failed command -> None
    assert resolve_secret("cmd:") is None                  # empty command -> None
    # a provider reads the resolved token (cmd: kept out of plaintext .env)
    monkeypatch.setenv("GH_TOKEN_X", "cmd:echo from-secret-mgr")
    from ssh_manager.providers.base import ProviderSpec
    gh = GitHub(ProviderSpec("ghx", kind="github", category="vcs", token_env="GH_TOKEN_X"))
    t = Target(alias="x", hostname="github.com", user="git",
               pubkey_path=tmp_pub(), pubkey_text="ssh-ed25519 AAAA x")
    assert gh._token(t) == "from-secret-mgr"


def test_resolve_secret_is_memoized_per_process(monkeypatch) -> None:
    # A `cmd:` secret must run ONCE even though a provider op resolves the token
    # 2-3x (capability check, env, the CLI call) - else a prompting/slow manager fires
    # repeatedly. Memoized by the command string.
    from ssh_manager.util import secrets

    class _R:
        returncode, stdout, stderr = 0, "tok\n", ""

    calls = {"n": 0}
    secrets._run_cmd_secret.cache_clear()
    monkeypatch.setattr("ssh_manager.util.secrets.proc.run",
                        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1) or _R())
    assert secrets.resolve_secret("cmd:fetch the-token") == "tok"
    assert secrets.resolve_secret("cmd:fetch the-token") == "tok"
    assert calls["n"] == 1                  # command ran once, despite two resolutions
    secrets._run_cmd_secret.cache_clear()


def tmp_pub():
    import tempfile
    from pathlib import Path
    p = Path(tempfile.mkstemp(suffix=".pub")[1])
    p.write_text("ssh-ed25519 AAAA x")
    return p


# --- gitlab adapter parity (idempotent deploy + body-matched verify/remove) -
def test_gitlab_deploy_idempotent_and_remove_by_body(monkeypatch, tmp_path) -> None:
    from ssh_manager.providers.gitlab import GitLab
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY me@host\n")
    gl = GitLab()
    monkeypatch.setenv("GLAB_TOKEN", "tok")
    monkeypatch.setattr("ssh_manager.providers.gitlab.proc.has", lambda n: True)
    deleted: list[str] = []
    added = {"n": 0}

    class R:
        def __init__(self, rc=0, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def fake_run(cmd, **kw):
        if cmd[:2] == ["glab", "api"] and "--method" not in cmd:        # list
            return R(0, json.dumps([
                {"id": 11, "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY x", "title": "a"}]))
        if "--method" in cmd:                                           # delete by id
            deleted.append(cmd[-1])
            return R(0)
        if cmd[:2] == ["glab", "ssh-key"]:                             # add
            added["n"] += 1
            return R(0)
        return R(0)

    monkeypatch.setattr("ssh_manager.providers.gitlab.proc.run", fake_run)
    t = Target(alias="x", hostname="gitlab.com", user="git",
               pubkey_path=pub, pubkey_text=pub.read_text())
    out = gl.deploy(t)                              # key already present -> idempotent
    assert out.verified and "already present" in out.detail and added["n"] == 0
    assert gl.verify(t) is True                     # body match
    assert gl.remove(t) is True and deleted == ["user/keys/11"]   # removed by body, not title


# --- knownhosts init (per-profile / all) -----------------------------------
def test_knownhosts_init_per_profile_and_all(svc: SshManagerService, monkeypatch) -> None:
    from ssh_manager.services.knownhosts import ScannedKey
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)

    def fake_scan(self, host, port=22):
        tok = host if port == 22 else f"[{host}]:{port}"
        return [ScannedKey(host, port, "ssh-ed25519",
                           f"{tok} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY", "SHA256:zz")]

    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", fake_scan)
    svc.reconcile()                                   # mints keys (auto-pin disabled in conftest)

    # one profile
    rep = svc.init_known_hosts(profile="personal")
    assert rep.profiles == ["personal"]
    kh = svc.paths.ssh_dir / "profiles" / "personal" / "known_hosts"
    assert kh.is_file() and "github.com ssh-ed25519" in kh.read_text()
    assert any(r.status == "pinned" and "SHA256:zz" in " ".join(r.fingerprints)
               for r in rep.results)
    # idempotent: re-init reports already-trusted, pins nothing new
    rep2 = svc.init_known_hosts(profile="personal")
    assert all(r.status == "already-trusted" for r in rep2.results)

    # all profiles
    rep_all = svc.init_known_hosts(all_profiles=True)
    assert {"work", "personal", "simtabi", "development"} <= set(rep_all.profiles)
    for prof in ("work", "simtabi", "development"):
        assert (svc.paths.ssh_dir / "profiles" / prof / "known_hosts").is_file()


def test_knownhosts_init_user_store(svc: SshManagerService, monkeypatch) -> None:
    from ssh_manager.services.knownhosts import ScannedKey
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)

    def fake_scan(self, host, port=22):
        tok = host if port == 22 else f"[{host}]:{port}"
        return [ScannedKey(host, port, "ssh-ed25519",
                           f"{tok} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY", "SHA256:zz")]

    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", fake_scan)
    svc.reconcile()
    rep = svc.init_known_hosts(user=True)             # per-user / global store only
    assert rep.profiles == ["(user)"]
    user_kh = svc.paths.ssh_dir / "known_hosts"       # top-level, NOT per-profile
    assert user_kh.is_file()
    text = user_kh.read_text()
    assert "github.com ssh-ed25519" in text
    # github.com appears once even though personal AND simtabi both use it (dedup)
    assert text.count("github.com ssh-ed25519") == 1
    assert all(r.profile == "(user)" for r in rep.results)
    # per-profile stores were NOT touched by --user alone
    assert not (svc.paths.ssh_dir / "profiles" / "personal" / "known_hosts").exists()


def test_knownhosts_init_unknown_profile_and_no_scope_error(svc: SshManagerService) -> None:
    with pytest.raises(SshManagerError, match="unknown profile"):
        svc.init_known_hosts(profile="nope")
    with pytest.raises(SshManagerError, match="PROFILE, --all, or --user"):
        svc.init_known_hosts()


def test_knownhosts_init_marks_unreachable(svc: SshManagerService, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: False)
    svc.reconcile()
    rep = svc.init_known_hosts(profile="work")        # unc is unreachable in this stub
    assert all(r.status == "unreachable" for r in rep.results)
    # the file is still created so the rendered UserKnownHostsFile path exists
    assert (svc.paths.ssh_dir / "profiles" / "work" / "known_hosts").is_file()


def _fake_scan(self, host, port=22):
    from ssh_manager.services.knownhosts import ScannedKey
    tok = host if port == 22 else f"[{host}]:{port}"
    return [ScannedKey(host, port, "ssh-ed25519",
                       f"{tok} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY", "SHA256:zz")]


def test_knownhosts_init_all_and_user_combined(svc: SshManagerService, monkeypatch) -> None:
    """--all --user writes BOTH the per-profile stores and the top-level store, and
    the user store aggregates each hostname:port once across profiles."""
    import stat
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", _fake_scan)
    svc.reconcile()

    rep = svc.init_known_hosts(all_profiles=True, user=True)
    assert "(user)" in rep.profiles and {"personal", "simtabi"} <= set(rep.profiles)

    user_kh = svc.paths.ssh_dir / "known_hosts"
    assert user_kh.is_file()
    # github.com is used by BOTH personal and simtabi but appears once in the user store
    assert user_kh.read_text().count("github.com ssh-ed25519") == 1
    # the top-level store created by --user must be 0644 (non-secret host pubkeys)
    assert stat.S_IMODE(user_kh.stat().st_mode) == 0o644
    # per-profile stores also written
    for prof in ("personal", "simtabi"):
        assert (svc.paths.ssh_dir / "profiles" / prof / "known_hosts").is_file()


def test_knownhosts_init_user_store_not_flagged_by_doctor(svc: SshManagerService,
                                                          monkeypatch) -> None:
    """The top-level ~/.ssh/known_hosts created by --user must not be reported as a
    perm issue by doctor (it is intentionally outside the managed-path set)."""
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", _fake_scan)
    svc.reconcile()
    svc.init_known_hosts(user=True)
    user_kh = svc.paths.ssh_dir / "known_hosts"
    assert user_kh.is_file()
    issues = svc._perm_issues(svc.paths.ssh_dir)
    assert not any("known_hosts" in i for i in issues), issues
    # doctor sees the top-level store as present
    assert svc.doctor().known_hosts is True


def test_knownhosts_init_user_dedups_by_host_and_port(svc: SshManagerService,
                                                      monkeypatch) -> None:
    """Two hosts sharing a hostname but on DIFFERENT ports must each get an entry in
    the user store (dedup is by (hostname, port), not hostname alone)."""
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", _fake_scan)
    # add a second host on github.com but a non-default port
    svc.host_add("personal", "github-alt", hostname="github.com", user="git", port=2222)
    svc.reconcile()
    svc.init_known_hosts(user=True)
    text = (svc.paths.ssh_dir / "known_hosts").read_text()
    assert "github.com ssh-ed25519" in text           # the :22 entry
    assert "[github.com]:2222 ssh-ed25519" in text     # the :2222 entry, bracket-port token
    # both port variants are distinct lines
    assert text.count("ssh-ed25519") >= 2


def test_knownhosts_init_force_does_not_duplicate_unchanged(svc: SshManagerService,
                                                            monkeypatch) -> None:
    """--force re-scans an already-trusted host; if the key is unchanged the store
    must not gain a duplicate line (add() dedups by exact line)."""
    monkeypatch.setattr("ssh_manager.util.net.tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr("ssh_manager.services.knownhosts.KnownHostsService.scan", _fake_scan)
    svc.reconcile()
    svc.init_known_hosts(profile="personal")
    kh = svc.paths.ssh_dir / "profiles" / "personal" / "known_hosts"
    before = kh.read_text()
    rep = svc.init_known_hosts(profile="personal", force=True)
    # force bypasses the already-trusted short-circuit -> status is 'pinned' again
    assert any(r.status == "pinned" for r in rep.results)
    # but the file must not have grown a duplicate of the same key line
    assert kh.read_text().count("github.com ssh-ed25519") == 1
    assert kh.read_text() == before


# --- doctor flags duplicate aliases across profiles -------------------------
def test_doctor_flags_cross_profile_alias_collision(svc: SshManagerService) -> None:
    svc.profile_add("dup1")
    svc.profile_add("dup2")
    svc.host_add("dup1", "server", hostname="1.1.1.1", user="a")
    svc.host_add("dup2", "server", hostname="2.2.2.2", user="b")   # same alias, other profile
    rep = svc.doctor()
    assert any(c.startswith("server ") for c in rep.alias_collisions)
    assert "shadowed" in rep.format()


# --- SSH_MANAGER_AUTO_PIN truthiness --------------------------------------------
def test_auto_pin_disabled_by_falsy_values(monkeypatch) -> None:
    from ssh_manager.services.facade import _auto_pin_disabled
    for v in ("0", "false", "FALSE", "no", "off", "Off"):
        monkeypatch.setenv("SSH_MANAGER_AUTO_PIN", v)
        assert _auto_pin_disabled() is True, v
    for v in ("1", "true", "yes", "on", ""):
        monkeypatch.setenv("SSH_MANAGER_AUTO_PIN", v)
        assert _auto_pin_disabled() is False, v


# --- known_hosts @marker tolerance -----------------------------------------
def test_host_in_known_hosts_handles_cert_authority_marker(tmp_path) -> None:
    from ssh_manager.services.facade import _host_in_known_hosts
    kh = tmp_path / "known_hosts"
    kh.write_text("@cert-authority github.com ssh-ed25519 AAAA\n"
                  "[sc.its.unc.edu]:443 ssh-rsa BBBB\n")
    assert _host_in_known_hosts(kh, "github.com") is True       # marker-prefixed
    assert _host_in_known_hosts(kh, "[sc.its.unc.edu]:443") is True
    assert _host_in_known_hosts(kh, "absent.example") is False


# --- generic REST provider --------------------------------------------------
def _rest_spec(rest: dict):
    from ssh_manager.providers.base import ProviderSpec
    return ProviderSpec("acme", kind="rest", category="vps",
                        token_env="ACME_TOKEN", rest=rest)


def _rest_target(tmp_path):
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABODY me@host\n")
    return Target(alias="x", hostname="h", user="root",
                  pubkey_path=pub, pubkey_text=pub.read_text())


def test_generic_rest_follows_next_field_pagination(monkeypatch, tmp_path) -> None:
    from ssh_manager.providers.cloud import GenericRest
    monkeypatch.setenv("ACME_TOKEN", "tok")
    pages = {
        "https://api.acme.com/v1/keys": {
            "keys": [{"id": "1", "name": "a", "public_key": "k1"}],
            "links": {"next": "https://api.acme.com/v1/keys?page=2"}},
        "https://api.acme.com/v1/keys?page=2": {
            "keys": [{"id": "2", "name": "b", "public_key": "k2"}],
            "links": {"next": None}},
    }
    monkeypatch.setattr("ssh_manager.providers.cloud.request_json",
                        lambda method, url, **kw: pages[url])
    prov = GenericRest(_rest_spec({
        "base_url": "https://api.acme.com/v1", "list_path": "/keys",
        "list_field": "keys", "next_field": "links.next"}))
    ids = [k.id for k in prov._list_keys("tok")]
    assert ids == ["1", "2"]                 # both pages followed via next_field


def test_generic_rest_remove_without_delete_path_returns_false(monkeypatch, tmp_path) -> None:
    from ssh_manager.providers.cloud import GenericRest
    monkeypatch.setenv("ACME_TOKEN", "tok")
    t = _rest_target(tmp_path)
    # the stored key matches the target by body, so remove WILL try to delete it
    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", lambda method, url, **kw: {
        "keys": [{"id": "1", "name": "a", "public_key": t.pubkey_text.strip()}]})
    prov = GenericRest(_rest_spec({
        "base_url": "https://api.acme.com/v1", "list_path": "/keys",
        "list_field": "keys", "public_key_field": "public_key"}))  # no delete_path
    # _delete_key raises HttpError (not configured); remove must report False, not
    # claim a phantom revocation - even though the key WAS matched.
    assert prov.remove(t) is False


# --- final deep-hunt fixes --------------------------------------------------
def test_duplicate_key_name_across_profiles_rejected() -> None:
    """rotate/deploy resolve a key_name back to a single profile dir; two profiles
    sharing a key_name would orphan/lock out one of them. Reject at load."""
    with pytest.raises(ManifestError):
        Manifest(profiles={
            "work": Profile(key_scope="shared", key_name="deploy",
                            hosts=[Host(alias="w", hostname="a.com", user="u")]),
            "home": Profile(key_scope="shared", key_name="deploy",
                            hosts=[Host(alias="h", hostname="b.com", user="u")]),
        })
    # explicit host.key_name collision across profiles is also rejected
    with pytest.raises(ManifestError):
        Manifest(profiles={
            "work": Profile(hosts=[Host(alias="x", hostname="a.com", user="u",
                                        key_name="shared-key")]),
            "home": Profile(hosts=[Host(alias="y", hostname="b.com", user="u",
                                        key_name="shared-key")]),
        })


def test_duplicate_key_name_within_one_shared_profile_ok() -> None:
    """The legitimate case (one shared profile, many hosts) must still validate."""
    Manifest(profiles={
        "work": Profile(key_scope="shared", key_name="deploy", hosts=[
            Host(alias="w1", hostname="a.com", user="u"),
            Host(alias="w2", hostname="c.com", user="u"),
        ]),
    })


def test_profile_named_old_not_excluded_from_expiry() -> None:
    """A profile literally named 'old' lives at profiles/old/<name>; its active
    keys must NOT be mistaken for /old/ archived predecessors and dropped from
    expiry/audit."""
    from datetime import date

    from ssh_manager.core.expiry import compute_states
    from ssh_manager.core.inventory import Inventory, KeyRecord, is_archived_path

    inv = Inventory()
    inv.record("SHA256:active", KeyRecord(
        profile="old", path="~/.ssh/profiles/old/old_h-ed25519",
        created="2025-01-01", expires_on="2025-02-01"))   # active, overdue
    inv.record("SHA256:archived", KeyRecord(
        profile="old", path="~/.ssh/profiles/old/old/old_h-ed25519",
        created="2025-01-01", expires_on="2025-02-01"))   # genuinely archived
    states = compute_states(inv, warn_before_days=[30], today=date(2026, 6, 14))
    names = {s.fingerprint for s in states}
    assert "SHA256:active" in names        # the active key in profile 'old' is seen
    assert "SHA256:archived" not in names  # the real /old/ predecessor is skipped
    assert not is_archived_path("~/.ssh/profiles/old/old_h-ed25519")
    assert is_archived_path("~/.ssh/profiles/old/old/old_h-ed25519")
