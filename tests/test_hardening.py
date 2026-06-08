"""Input hardening: a manifest can't inject ssh config, escape the key tree, or
smuggle leading-dash arguments into ssh (the manifest is rendered verbatim and its
names become filesystem paths)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_manager.core.manifest import Manifest


def _m(host_extra=None, profiles=None):
    h = {"alias": "h", "hostname": "x.example", "user": "u", "key_name": "w_h-ed25519"}
    h.update(host_extra or {})
    return {"version": 1, "profiles": profiles or {"w": {"hosts": [h]}}}


@pytest.mark.parametrize("extra", [
    {"raw_options": {"ProxyCommand": "touch /tmp/pwned"}},   # command execution
    {"raw_options": {"LocalCommand": "sh"}},
    {"raw_options": {"Include": "/etc/evil"}},
    {"hostname": "real\n    ProxyCommand sh -c x"},          # newline -> config injection
    {"user": "git\nHost *\n  ProxyCommand sh"},
    {"alias": "ok\n  ForwardAgent yes"},
    {"hostname": "-oProxyCommand=sh"},                       # leading-dash arg injection
    {"user": "-oProxyCommand=sh"},
    {"alias": "../../etc/x"},                                # path traversal
    {"key_name": "../../authorized_keys"},
])
def test_dangerous_host_values_rejected(extra) -> None:
    with pytest.raises(ValidationError):
        Manifest.model_validate(_m(host_extra=extra))


@pytest.mark.parametrize("name", ["../../tmp/evil", "a/b", "..", "-dash", "with\nnewline"])
def test_dangerous_profile_names_rejected(name) -> None:
    with pytest.raises(ValidationError):
        Manifest.model_validate(_m(profiles={name: {"hosts": []}}))


def test_dangerous_global_options_rejected() -> None:
    data = _m()
    data["defaults"] = {"global_options": {"ProxyCommand": "sh"}}
    with pytest.raises(ValidationError):
        Manifest.model_validate(data)


def test_duplicate_alias_across_profiles_silently_shadows() -> None:
    """GAP (characterization): the same Host alias in two profiles is accepted, and
    both render into profiles/*/config which are all pulled in by `Include
    profiles/*/config`. OpenSSH applies the FIRST matching Host block, so the second
    profile's host (different HostName/key) is silently shadowed - `ssh server1` may
    hit the wrong box with the wrong key. Nothing validates or flags this today.

    This test pins the current behavior so a future doctor/validation check that
    surfaces cross-profile alias collisions will deliberately update it."""
    from ssh_manager.core.manifest import Host, Profile
    from ssh_manager.core.renderer import render_all
    m = Manifest.model_validate({
        "version": 1,
        "profiles": {
            "work": {"hosts": [{"alias": "server1", "hostname": "1.1.1.1",
                                "user": "a", "key_name": "work_s1-ed25519"}]},
            "home": {"hosts": [{"alias": "server1", "hostname": "2.2.2.2",
                                "user": "b", "key_name": "home_s1-ed25519"}]},
        },
    })
    out = render_all(m, emit_use_keychain=False)
    # both blocks exist (duplicate alias accepted, no de-dup) -> ssh sees two
    assert "Host server1" in out["profiles/work/config"]
    assert "Host server1" in out["profiles/home/config"]
    # keep the unused imports meaningful for future de-dup logic
    assert isinstance(m.profiles["work"], Profile)
    assert all(isinstance(h, Host) for p in m.profiles.values() for h in p.hosts)


def test_safe_realistic_values_still_load() -> None:
    # dots in alias/hostname, ProxyJump (a host, not a command), kebab key names
    ok = _m(host_extra={"alias": "github-simtabi", "hostname": "github.com",
                        "raw_options": {"ProxyJump": "bastion.example"}})
    m = Manifest.model_validate(ok)
    assert m.profiles["w"].hosts[0].raw_options["ProxyJump"] == "bastion.example"
