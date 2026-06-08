"""Cloud VPS provider adapters - manage *account* SSH keys via REST.

These manage the keys in your provider dashboard (DigitalOcean, Vultr, Hetzner,
Linode) - the ones you pick when creating a server - via each provider's REST
API. They plug into the same Strategy as GitHub/GitLab: ``deploy`` adds the key,
``verify``/``list_deployed`` list it, ``remove`` deletes it (matched by key body).
No token → degrade to the dashboard/manual path. Refactored from a standalone VPS
key tool; HTTP goes through ``util.http`` (stdlib, retrying).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ..core.authorized_keys import key_body
from ..util.http import HttpError, request_json
from ..util.secrets import resolve_secret
from .base import DeployOutcome, Provider, Target

_MAX_PAGES = 50


@dataclass(frozen=True)
class RemoteKey:
    id: str
    name: str
    body: str           # the key's base64 body, for matching


def _assert_paginated(next_url: str | None) -> None:
    """A non-None next-page link after _MAX_PAGES means the API never terminated
    pagination - error rather than silently trust a truncated list (verify/remove
    would otherwise falsely conclude a key is absent)."""
    if next_url:
        raise HttpError(f"pagination did not terminate after {_MAX_PAGES} pages")


def _dig(data: Any, dotted: str) -> Any:
    """Walk a dotted path into nested dicts (``meta.links.next``), or None."""
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


class RestVpsProvider(Provider):
    """Account-key management over a provider REST API (category ``vps``)."""

    category = "vps"
    default_env = ""    # subclass: default token env var
    dashboard = ""      # subclass: human dashboard URL (manual fallback)

    def _token(self, target: Target) -> str | None:
        var = (target.token_env or (self.spec.token_env if self.spec else None)
               or self.default_env)
        if not var:
            return None
        return resolve_secret(os.environ.get(var))

    # HTTP (override _auth_headers for non-Bearer auth, e.g. Scaleway)
    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _get(self, token: str, url: str) -> Any:
        return request_json("GET", url, headers=self._auth_headers(token))

    def _post(self, token: str, url: str, body: Any) -> Any:
        return request_json("POST", url, headers=self._auth_headers(token), body=body)

    def _del(self, token: str, url: str) -> Any:
        return request_json("DELETE", url, headers=self._auth_headers(token))

    def _put(self, token: str, url: str, body: Any) -> Any:
        return request_json("PUT", url, headers=self._auth_headers(token), body=body)

    def _patch(self, token: str, url: str, body: Any) -> Any:
        return request_json("PATCH", url, headers=self._auth_headers(token), body=body)

    @staticmethod
    def _key_title(filename: str, body: str) -> str:
        # Include a short body fragment so two DIFFERENT keys sharing a filename
        # (the live key and a rotation's staged replacement) never collide on
        # providers that enforce unique key names (e.g. Hetzner Cloud).
        return f"ssh-manager {filename} {body[:12]}" if body else f"ssh-manager {filename}"

    def deploy(self, target: Target) -> DeployOutcome:
        token = self._token(target)
        if not token:
            return self._manual(target)
        want = key_body(target.pubkey_text)
        title = self._key_title(target.pubkey_path.name, want)
        try:
            existing = next(
                (k for k in self._list_keys(token) if k.body and key_body(k.body) == want),
                None)
            if existing is not None:
                # Idempotent: key already in the account, don't duplicate it. Only
                # re-canonicalise the title of a key we own - including keys the old
                # ``sshmgr`` name deployed (re-titled to ``ssh-manager`` on next deploy)
                # - never rename a key the user added/named by hand in the dashboard.
                owned = existing.name.startswith(("ssh-manager ", "sshmgr "))
                if (existing.name != title and owned
                        and self._rename_key(token, existing.id, title)):
                    return DeployOutcome(f"{self.name}-api", verified=True,
                                         detail=f"already present; renamed to '{title}'")
                return DeployOutcome(f"{self.name}-api", verified=True,
                                     detail=f"already present (as '{existing.name}')")
            self._add_key(token, title, target.pubkey_text.strip())
        except HttpError as exc:
            return DeployOutcome(f"{self.name}-api", verified=False, detail=str(exc),
                                 error=True)
        return DeployOutcome(f"{self.name}-api", verified=True,
                             detail=f"added to {self.name} account as '{title}'")

    def rename(self, target: Target, new_title: str) -> bool:
        """Rename the account key matching this pubkey (by body). True if renamed."""
        token = self._token(target)
        if not token:
            return False
        want = key_body(target.pubkey_text)
        try:
            for k in self._list_keys(token):
                if k.body and key_body(k.body) == want:
                    return self._rename_key(token, k.id, new_title)
        except HttpError:
            return False
        return False

    def verify(self, target: Target) -> bool:
        token = self._token(target)
        if not token:
            return False
        want = key_body(target.pubkey_text)
        try:
            return any(k.body and key_body(k.body) == want for k in self._list_keys(token))
        except HttpError:
            return False

    def list_deployed(self, target: Target) -> list[str]:
        token = self._token(target)
        if not token:
            return []
        try:
            return [k.name for k in self._list_keys(token)]
        except HttpError:
            return []

    def remove(self, target: Target) -> bool:
        token = self._token(target)
        if not token:
            return False
        want = key_body(target.pubkey_text)
        try:
            for k in self._list_keys(token):
                if k.body and key_body(k.body) == want:
                    self._delete_key(token, k.id)
                    return True
        except HttpError:
            return False
        return False

    def manage_url(self, target: Target) -> str | None:
        if self.spec and self.spec.resolved_keys_url():
            return self.spec.resolved_keys_url()
        return self.dashboard or None

    # subclass interface
    def _list_keys(self, token: str) -> list[RemoteKey]:
        raise NotImplementedError

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        raise NotImplementedError

    def _delete_key(self, token: str, key_id: str) -> None:
        raise NotImplementedError

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        """Rename the provider-side key. Returns True if it acted (subclasses that
        can't rename return False rather than silently claiming success)."""
        raise NotImplementedError


class DigitalOcean(RestVpsProvider):
    name = "digitalocean"
    default_env = "DIGITALOCEAN_TOKEN"
    dashboard = "https://cloud.digitalocean.com/account/security"
    _base = "https://api.digitalocean.com/v2"

    def _list_keys(self, token: str) -> list[RemoteKey]:
        out: list[RemoteKey] = []
        url: str | None = f"{self._base}/account/keys?per_page=200"
        for _ in range(_MAX_PAGES):
            if not url:
                break
            data = self._get(token, url)
            out += [RemoteKey(str(k["id"]), k.get("name", ""), k.get("public_key", ""))
                    for k in data.get("ssh_keys", [])]
            url = ((data.get("links") or {}).get("pages") or {}).get("next")
        _assert_paginated(url)
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        self._post(token, f"{self._base}/account/keys",
                   {"name": name, "public_key": public_key})

    def _delete_key(self, token: str, key_id: str) -> None:
        self._del(token, f"{self._base}/account/keys/{key_id}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        self._put(token, f"{self._base}/account/keys/{key_id}", {"name": new_name})
        return True


class Vultr(RestVpsProvider):
    name = "vultr"
    default_env = "VULTR_API_KEY"
    dashboard = "https://my.vultr.com/settings/#settingssshkeys"
    _base = "https://api.vultr.com/v2"

    def _list_keys(self, token: str) -> list[RemoteKey]:
        out: list[RemoteKey] = []
        url: str | None = f"{self._base}/ssh-keys?per_page=500"
        for _ in range(_MAX_PAGES):
            if not url:
                break
            data = self._get(token, url)
            out += [RemoteKey(str(k["id"]), k.get("name", ""), k.get("ssh_key", ""))
                    for k in data.get("ssh_keys", [])]
            nxt = (data.get("meta", {}).get("links", {}) or {}).get("next")
            url = (f"{self._base}/ssh-keys?per_page=500&cursor={quote(str(nxt), safe='')}"
                   if nxt else None)
        _assert_paginated(url)
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        self._post(token, f"{self._base}/ssh-keys", {"name": name, "ssh_key": public_key})

    def _delete_key(self, token: str, key_id: str) -> None:
        self._del(token, f"{self._base}/ssh-keys/{key_id}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        self._patch(token, f"{self._base}/ssh-keys/{key_id}", {"name": new_name})
        return True


class Hetzner(RestVpsProvider):
    name = "hetzner"
    default_env = "HCLOUD_TOKEN"
    dashboard = "https://console.hetzner.cloud/"
    _base = "https://api.hetzner.cloud/v1"

    def _list_keys(self, token: str) -> list[RemoteKey]:
        out: list[RemoteKey] = []
        url: str | None = f"{self._base}/ssh_keys?per_page=50"
        for _ in range(_MAX_PAGES):
            if not url:
                break
            data = self._get(token, url)
            out += [RemoteKey(str(k["id"]), k.get("name", ""), k.get("public_key", ""))
                    for k in data.get("ssh_keys", [])]
            nxt = (data.get("meta", {}).get("pagination", {}) or {}).get("next_page")
            url = f"{self._base}/ssh_keys?per_page=50&page={nxt}" if nxt else None
        _assert_paginated(url)
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        self._post(token, f"{self._base}/ssh_keys", {"name": name, "public_key": public_key})

    def _delete_key(self, token: str, key_id: str) -> None:
        self._del(token, f"{self._base}/ssh_keys/{key_id}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        self._put(token, f"{self._base}/ssh_keys/{key_id}", {"name": new_name})
        return True


class Linode(RestVpsProvider):
    name = "linode"
    default_env = "LINODE_TOKEN"
    dashboard = "https://cloud.linode.com/profile/keys"
    _base = "https://api.linode.com/v4"

    def _list_keys(self, token: str) -> list[RemoteKey]:
        out: list[RemoteKey] = []
        page = 1
        done = False
        for _ in range(_MAX_PAGES):
            data = self._get(token, f"{self._base}/profile/sshkeys?page={page}&page_size=100")
            out += [RemoteKey(str(k["id"]), k.get("label", ""), k.get("ssh_key", ""))
                    for k in data.get("data", [])]
            if page >= int(data.get("pages", 1)):
                done = True
                break
            page += 1
        if not done:   # never trust a truncated list (verify/remove would misfire)
            raise HttpError(f"pagination did not terminate after {_MAX_PAGES} pages")
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        self._post(token, f"{self._base}/profile/sshkeys", {"label": name, "ssh_key": public_key})

    def _delete_key(self, token: str, key_id: str) -> None:
        self._del(token, f"{self._base}/profile/sshkeys/{key_id}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        self._put(token, f"{self._base}/profile/sshkeys/{key_id}", {"label": new_name})
        return True


class Scaleway(RestVpsProvider):
    """Scaleway scopes keys to a project (needs SCW_PROJECT_ID) and uses its own
    auth header rather than a Bearer token."""

    name = "scaleway"
    default_env = "SCW_SECRET_KEY"
    dashboard = "https://console.scaleway.com/project/credentials"
    _base = "https://api.scaleway.com/iam/v1alpha1"

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"X-Auth-Token": token}

    def _project(self) -> str | None:
        return os.environ.get("SCW_PROJECT_ID") or None

    def _list_keys(self, token: str) -> list[RemoteKey]:
        project = self._project()
        if not project:
            # Don't silently return [] - that would make verify/remove falsely
            # report "key absent" and deploy add a duplicate.
            raise HttpError("Scaleway requires SCW_PROJECT_ID (the project the keys "
                            "belong to) - set it alongside SCW_SECRET_KEY")
        out: list[RemoteKey] = []
        page = 1
        done = False
        for _ in range(_MAX_PAGES):
            data = self._get(
                token,
                f"{self._base}/ssh-keys?project_id={quote(project, safe='')}"
                f"&page={page}&page_size=100")
            batch = data.get("ssh_keys", [])
            out += [RemoteKey(str(k["id"]), k.get("name", ""), k.get("public_key", ""))
                    for k in batch]
            if len(batch) < 100:
                done = True
                break
            page += 1
        if not done:   # a full last batch after _MAX_PAGES means more keys remain
            raise HttpError(f"pagination did not terminate after {_MAX_PAGES} pages")
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        self._post(token, f"{self._base}/ssh-keys",
                   {"name": name, "public_key": public_key, "project_id": self._project()})

    def _delete_key(self, token: str, key_id: str) -> None:
        self._del(token, f"{self._base}/ssh-keys/{key_id}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        self._patch(token, f"{self._base}/ssh-keys/{key_id}", {"name": new_name})
        return True


class GenericRest(RestVpsProvider):
    """A REST provider defined entirely by config (``providers.json`` ``rest``
    block) - add *any* cloud with a simple key API without writing code. Good for
    an API that authenticates with one header, lists keys under one JSON field,
    and creates/deletes by id under a predictable path."""

    def _cfg(self) -> dict[str, Any]:
        return (self.spec.rest if self.spec and self.spec.rest else {}) or {}

    def _auth_headers(self, token: str) -> dict[str, str]:
        c = self._cfg()
        headers = dict(c.get("extra_headers", {}))
        name = c.get("auth_header_name", "Authorization")
        headers[name] = f"{c.get('auth_header_prefix', 'Bearer ')}{token}"
        return headers

    def _list_keys(self, token: str) -> list[RemoteKey]:
        c = self._cfg()
        if not c.get("base_url") or not c.get("list_field"):
            raise HttpError("generic 'rest' provider needs a `rest` config with at "
                            "least base_url + list_field in providers.json")
        base = c["base_url"]
        # The token is sent as a header to base_url; require TLS so it can't be
        # exfiltrated to a plaintext / link-local endpoint via an edited providers.json.
        if not str(base).lower().startswith("https://"):
            raise HttpError(f"generic 'rest' base_url must be https:// (got {base!r})")
        idf, nmf, pkf = (c.get("id_field", "id"), c.get("name_field", "name"),
                         c.get("public_key_field", "public_key"))
        # Optional pagination: `next_field` is a dotted path to an absolute next-page
        # URL (e.g. "links.next"). Without it the list is assumed to be one page.
        next_field = c.get("next_field")
        out: list[RemoteKey] = []
        url: str | None = f"{base}{c.get('list_path', '')}"
        for _ in range(_MAX_PAGES):
            if not url:
                break
            data = self._get(token, url)
            items = data.get(c["list_field"], []) if isinstance(data, dict) else (data or [])
            out += [RemoteKey(str(it.get(idf, "")), it.get(nmf, ""), it.get(pkf, ""))
                    for it in items]
            url = _dig(data, next_field) if (next_field and isinstance(data, dict)) else None
        _assert_paginated(url)
        return out

    def _add_key(self, token: str, name: str, public_key: str) -> None:
        c = self._cfg()
        base = c.get("base_url", "")
        path = c.get("create_path") or c.get("list_path", "")
        body = {c.get("create_name_field", "name"): name,
                c.get("create_key_field", "public_key"): public_key}
        self._post(token, f"{base}{path}", body)

    def _delete_key(self, token: str, key_id: str) -> None:
        c = self._cfg()
        if not c.get("delete_path"):
            # No delete endpoint configured: raise rather than let `remove` claim a
            # revocation that never happened (a silent false success in a security tool).
            raise HttpError("generic 'rest' provider has no `delete_path` configured "
                            "- revoke the key manually in the provider dashboard")
        self._del(token, f"{c.get('base_url', '')}{c['delete_path'].format(id=key_id)}")

    def _rename_key(self, token: str, key_id: str, new_name: str) -> bool:
        c = self._cfg()
        if not c.get("rename_path"):
            return False  # rename not configured - leave the title as-is, report no-op
        url = f"{c.get('base_url', '')}{c['rename_path'].format(id=key_id)}"
        body = {c.get("rename_field", "name"): new_name}
        method = c.get("rename_method", "PUT").upper()
        (self._patch if method == "PATCH" else self._put)(token, url, body)
        return True
