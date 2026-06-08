"""Cloud VPS account-key adapters (DO/Vultr/Hetzner/Linode) + authorized_keys helpers."""
from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest

from ssh_manager.core.authorized_keys import (
    add_key_to_text,
    count_keys,
    is_valid_public_key,
    key_body,
    key_lines,
    remove_key_from_text,
    same_key,
)
from ssh_manager.providers.base import Target
from ssh_manager.providers.registry import resolve

PROVIDERS = Path(__file__).resolve().parent.parent / "config" / "providers.json"


def _body(tag: str, key_type: bytes = b"ssh-ed25519") -> str:
    """A real SSH wire-format key body (length-prefixed type + payload), distinct
    per tag - valid for the strict parser, which checks the encoded wire type."""
    payload = (tag.encode() * 64)[:32]
    blob = struct.pack(">I", len(key_type)) + key_type + struct.pack(">I", 32) + payload
    return base64.b64encode(blob).decode()


BLOB, RSA = _body("blob"), _body("rsa", b"ssh-rsa")
PUB = f"ssh-ed25519 {_body('pub')} me@host\n"


# pure authorized_keys helpers
def test_key_body_same_key_and_validation() -> None:
    a = f"ssh-ed25519 {BLOB} comment-one"
    b = f'restrict,command="x" ssh-ed25519 {BLOB} comment-two'  # options + diff comment
    assert key_body(a) == BLOB
    assert same_key(a, b)                       # matched by body, ignoring options/comment
    assert is_valid_public_key(a)
    assert not is_valid_public_key("ssh-ed25519 not-base64! junk")   # rejects garbage
    assert not is_valid_public_key("# just a comment")
    assert key_body("garbage line here") == ""  # not a key -> empty body
    # a base64-LOOKING comment word with the wrong wire type is rejected
    fake = base64.b64encode(b"this is not an ssh key blob at all").decode()
    assert not is_valid_public_key(f"ssh-ed25519 {fake} comment")
    # wire type must match the type token
    assert not is_valid_public_key(f"ssh-rsa {BLOB} comment")        # BLOB is ed25519


def test_add_dedupes_remove_by_body_and_count() -> None:
    text = f"ssh-rsa {RSA} alice\n"
    text, added = add_key_to_text(text, f"ssh-ed25519 {BLOB} bob")
    assert added and count_keys(text) == 2
    _, again = add_key_to_text(text, f"ssh-ed25519 {BLOB} bob-renamed")
    assert again is False                        # same body -> not re-added
    with pytest.raises(ValueError, match="not a valid public key"):
        add_key_to_text(text, "this is not a key")
    text, n = remove_key_from_text(text, f"ssh-ed25519 {BLOB} whatever")
    assert n == 1 and key_lines(text) == [f"ssh-rsa {RSA} alice"]


# VPS adapters (mock the HTTP layer)
def _target(tmp_path: Path) -> Target:
    p = tmp_path / "k.pub"
    p.write_text(PUB)
    return Target(alias="droplet", hostname="1.2.3.4", user="root",
                  pubkey_path=p, pubkey_text=p.read_text())


def test_digitalocean_deploy_verify_remove(tmp_path, monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    store: list[dict] = []

    def fake(method, url, *, token=None, body=None, **kw):
        calls.append((method, url))
        if method == "GET":
            return {"ssh_keys": list(store), "links": {}}
        if method == "POST":
            store.append({"id": 7, "name": body["name"], "public_key": body["public_key"]})
            return {"ssh_key": store[-1]}
        if method == "DELETE":
            store.clear()
            return {}
        return {}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "tok")
    do = resolve("digitalocean", PROVIDERS)
    assert do.category == "vps"
    t = _target(tmp_path)
    out = do.deploy(t)
    assert out.method == "digitalocean-api" and out.verified
    assert do.verify(t) is True                  # the key body is now present
    assert do.remove(t) is True                  # found by body + deleted
    assert do.verify(t) is False                 # gone


def _deploy_with_existing(tmp_path, monkeypatch, existing_name: str):
    store = [{"id": "9", "name": existing_name, "public_key": PUB.strip()}]
    seen: dict = {}

    def fake(method, url, *, headers=None, body=None, **kw):
        if method == "GET":
            return {"ssh_keys": store, "links": {}}
        if method == "PUT":                         # DigitalOcean rename
            seen["renamed_to"] = body["name"]
            return {}
        if method == "POST":
            seen["added"] = True
            return {}
        return {}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "tok")
    do = resolve("digitalocean", PROVIDERS)
    return do.deploy(_target(tmp_path)), seen


def test_deploy_renames_stale_sshmgr_title(tmp_path, monkeypatch) -> None:
    # a key the OLD `sshmgr` name deployed is recognised as ours and re-titled
    out, seen = _deploy_with_existing(tmp_path, monkeypatch, "sshmgr old.pub")
    assert out.verified and "renamed" in out.detail    # we own it: title fixed
    assert seen["renamed_to"].startswith("ssh-manager ")
    assert "added" not in seen                          # idempotent, no duplicate


def test_deploy_leaves_user_named_key_untouched(tmp_path, monkeypatch) -> None:
    out, seen = _deploy_with_existing(tmp_path, monkeypatch, "my-laptop-key")
    assert out.verified and "already present" in out.detail
    assert "renamed_to" not in seen                     # never rename a user's own label
    assert "added" not in seen


def test_public_rename_by_body(tmp_path, monkeypatch) -> None:
    store = [{"id": "5", "name": "a", "public_key": PUB.strip()}]
    seen: dict = {}

    def fake(method, url, *, headers=None, body=None, **kw):
        if method == "GET":
            return {"ssh_keys": store, "links": {}}
        if method == "PUT":
            seen["name"] = body["name"]
            return {}
        return {}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "tok")
    do = resolve("digitalocean", PROVIDERS)
    assert do.rename(_target(tmp_path), "new-title") is True
    assert seen["name"] == "new-title"


def _adaptive_fake(store: list[dict]):
    """A mock REST backend that answers in EVERY provider's JSON shape, so one
    test can drive each adapter's real endpoints/fields end to end."""
    def fake(method, url, *, headers=None, body=None, **kw):
        if method == "GET":
            keys = [{"id": k["id"], "name": k["name"], "label": k["name"],
                     "public_key": k["pub"], "ssh_key": k["pub"]} for k in store]
            return {"ssh_keys": keys, "data": keys, "links": {}, "meta": {}, "pages": 1}
        if method == "POST":
            store.append({"id": str(len(store) + 1),
                          "name": body.get("name") or body.get("label"),
                          "pub": body.get("public_key") or body.get("ssh_key")})
            return {"ssh_key": {}, "id": "x"}
        if method in ("PUT", "PATCH"):
            store[0]["name"] = body.get("name") or body.get("label")
            return {}
        if method == "DELETE":
            store.clear()
            return {}
        return {}
    return fake


@pytest.mark.parametrize("name,env", [
    ("digitalocean", "DIGITALOCEAN_TOKEN"),
    ("vultr", "VULTR_API_KEY"),
    ("hetzner", "HCLOUD_TOKEN"),
    ("linode", "LINODE_TOKEN"),
    ("scaleway", "SCW_SECRET_KEY"),
])
def test_every_vps_adapter_full_lifecycle(name, env, tmp_path, monkeypatch) -> None:
    store: list[dict] = []
    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", _adaptive_fake(store))
    monkeypatch.setenv(env, "tok")
    if name == "scaleway":
        monkeypatch.setenv("SCW_PROJECT_ID", "proj")
    prov = resolve(name, PROVIDERS)
    t = _target(tmp_path)
    assert prov.deploy(t).verified                  # add via the adapter's endpoint/fields
    assert prov.verify(t) is True                   # list parses + body matches
    assert prov.list_deployed(t)                    # names come back
    assert prov.rename(t, "sshmgr renamed") is True  # PUT/PATCH the right path/field
    assert store[0]["name"] == "sshmgr renamed"
    assert prov.remove(t) is True                   # delete by id
    assert prov.verify(t) is False                  # gone


def test_vps_without_token_degrades_to_dashboard(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("HCLOUD_TOKEN", raising=False)
    h = resolve("hetzner", PROVIDERS)
    out = h.deploy(_target(tmp_path))
    assert out.method == "manual"
    assert h.manage_url(_target(tmp_path)) == "https://console.hetzner.cloud/"


def test_all_vps_resolve_with_category_vps() -> None:
    for name in ["digitalocean", "vultr", "hetzner", "linode", "scaleway"]:
        assert resolve(name, PROVIDERS).category == "vps"


def test_scaleway_uses_xauth_header_and_project(tmp_path, monkeypatch) -> None:
    seen: list[dict] = []

    def fake(method, url, *, headers=None, body=None, **kw):
        seen.append({"method": method, "url": url, "headers": headers, "body": body})
        return {"ssh_keys": [], "id": "1"}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("SCW_SECRET_KEY", "sec")
    monkeypatch.setenv("SCW_PROJECT_ID", "proj-123")
    sc = resolve("scaleway", PROVIDERS)
    sc.deploy(_target(tmp_path))
    post = next(c for c in seen if c["method"] == "POST")
    assert post["headers"] == {"X-Auth-Token": "sec"}      # not Bearer
    assert post["body"]["project_id"] == "proj-123"        # project-scoped


def test_generic_rest_provider_from_config(tmp_path, monkeypatch) -> None:
    seen: list[dict] = []

    def fake(method, url, *, headers=None, body=None, **kw):
        seen.append({"method": method, "url": url, "headers": headers})
        return {"ssh_keys": []}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("EXAMPLE_TOKEN", "tok")
    gr = resolve("example-rest", PROVIDERS)         # kind 'rest', defined entirely in config
    assert type(gr).__name__ == "GenericRest"
    gr.deploy(_target(tmp_path))
    post = next(c for c in seen if c["method"] == "POST")
    assert post["url"] == "https://api.example.com/v1/ssh_keys"   # base_url + create_path
    assert post["headers"]["Authorization"].startswith("Bearer ")


def test_http_retries_then_raises(monkeypatch) -> None:
    import urllib.error

    from ssh_manager.util.http import HttpError, request_json
    attempts = {"n": 0}

    def boom(req, timeout=0):
        attempts["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)

    monkeypatch.setattr("ssh_manager.util.http._OPENER.open", boom)
    with pytest.raises(HttpError, match="503"):
        request_json("GET", "https://x/api", token="t", retries=2, _sleep=lambda s: None)
    assert attempts["n"] == 3                     # GET (idempotent): initial + 2 retries


def test_http_post_not_retried_on_5xx(monkeypatch) -> None:
    import urllib.error

    from ssh_manager.util.http import HttpError, request_json
    attempts = {"n": 0}

    def boom(req, timeout=0):
        attempts["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 502, "bad gw", {}, None)

    monkeypatch.setattr("ssh_manager.util.http._OPENER.open", boom)
    with pytest.raises(HttpError):
        request_json("POST", "https://x/api", token="t", body={"a": 1},
                     retries=3, _sleep=lambda s: None)
    assert attempts["n"] == 1                     # POST is NOT retried (could duplicate)


def test_http_non_json_response_raises(monkeypatch) -> None:
    from ssh_manager.util.http import HttpError, request_json

    class _Resp:
        status = 200
        def read(self):
            return b"<html>error page</html>"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr("ssh_manager.util.http._OPENER.open",
                        lambda req, timeout=0: _Resp())
    with pytest.raises(HttpError, match="non-JSON"):
        request_json("GET", "https://x/api", token="t")


def test_scaleway_without_project_surfaces_clear_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", lambda *a, **k: {})
    monkeypatch.setenv("SCW_SECRET_KEY", "s")
    monkeypatch.delenv("SCW_PROJECT_ID", raising=False)
    out = resolve("scaleway", PROVIDERS).deploy(_target(tmp_path))
    assert not out.verified and "SCW_PROJECT_ID" in out.detail   # not a silent "absent"


def test_generic_rest_missing_config_surfaces_error(tmp_path, monkeypatch) -> None:
    from ssh_manager.providers.base import ProviderSpec
    from ssh_manager.providers.cloud import GenericRest
    monkeypatch.setenv("X_TOKEN", "t")
    gr = GenericRest(ProviderSpec("x", kind="rest", category="vps",
                                  token_env="X_TOKEN", rest={}))
    out = gr.deploy(_target(tmp_path))
    assert not out.verified and "rest" in out.detail.lower()


def test_pagination_non_termination_raises(tmp_path, monkeypatch) -> None:
    # GET always returns a next page -> the guard must raise, not loop/truncate
    def fake(method, url, *, headers=None, body=None, **kw):
        return {"ssh_keys": [],
                "links": {"pages": {"next": "https://api.digitalocean.com/v2/x?page=2"}}}

    monkeypatch.setattr("ssh_manager.providers.cloud.request_json", fake)
    monkeypatch.setenv("DIGITALOCEAN_TOKEN", "t")
    out = resolve("digitalocean", PROVIDERS).deploy(_target(tmp_path))
    assert not out.verified and "pagination" in out.detail
