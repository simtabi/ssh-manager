"""GitHub adapter - `gh` CLI; works for github.com AND GitHub Enterprise.

The instance host comes from the ProviderSpec (``host``). ``gh`` selects the
target instance via the ``GH_HOST`` environment variable (it has no ``--hostname``
flag), and authenticates with ``GH_TOKEN`` for github.com or ``GH_ENTERPRISE_TOKEN``
for a GHES host. Credentials resolve per host via ``token_env`` (two accounts on
one instance don't collide). No token/CLI -> web-panel/manual.

Key listing/removal go through ``gh api user/keys`` (stable JSON), and removal is
matched by the key *body* - never by title - so rotation can't revoke the wrong
key when the old and new keys share a filename-derived title.
"""
from __future__ import annotations

import json
import os

from ..core.authorized_keys import key_body
from ..util import proc
from ..util.secrets import resolve_secret
from .base import DeployOutcome, Provider, Target


class GitHub(Provider):
    name = "github"
    category = "vcs"

    def _host(self) -> str:
        return (self.spec.host if self.spec and self.spec.host else "github.com")

    def _is_enterprise(self) -> bool:
        return self._host() != "github.com"

    def _token(self, target: Target) -> str | None:
        var = target.token_env or (self.spec.token_env if self.spec else None) or "GH_TOKEN"
        return resolve_secret(os.environ.get(var))

    def _env(self, target: Target) -> dict[str, str] | None:
        token = self._token(target)
        if not token:
            return None
        env = {"GH_HOST": self._host()}
        # gh reads GH_ENTERPRISE_TOKEN for a GHES host, GH_TOKEN for github.com.
        env["GH_ENTERPRISE_TOKEN" if self._is_enterprise() else "GH_TOKEN"] = token
        return env

    def _can_api(self, target: Target) -> bool:
        return proc.has("gh") and self._token(target) is not None

    def _list_remote(self, target: Target) -> list[dict[str, object]] | None:
        """The account's authentication keys via the REST API. None on failure
        (so callers never mistake an API error for an empty key list)."""
        r = proc.run(["gh", "api", "--paginate", "user/keys"],
                     env=self._env(target), timeout=30)
        if r.returncode != 0:
            return None
        try:
            data = json.loads(r.stdout or "[]")
        except ValueError:
            return None
        return data if isinstance(data, list) else None

    def deploy(self, target: Target) -> DeployOutcome:
        if not self._can_api(target):
            return self._manual(target)
        want = key_body(target.pubkey_text)
        rows = self._list_remote(target)
        if rows is not None and want and any(key_body(str(r.get("key", ""))) == want for r in rows):
            return DeployOutcome("github-gh", verified=True, detail="already present")
        title = f"ssh-manager {target.pubkey_path.name}"
        r = proc.run(
            ["gh", "ssh-key", "add", str(target.pubkey_path), "--title", title],
            env=self._env(target), timeout=30,
        )
        if r.returncode != 0:
            return DeployOutcome("github-gh", verified=False, detail=r.stderr.strip(),
                                 error=True)
        return DeployOutcome("github-gh", verified=True, detail=f"added as '{title}'")

    def verify(self, target: Target) -> bool:
        if self._can_api(target):
            want = key_body(target.pubkey_text)
            rows = self._list_remote(target)
            if rows is None or not want:
                return False
            return any(key_body(str(r.get("key", ""))) == want for r in rows)
        if target.identity_path is None or not proc.has("ssh"):
            return False
        kh = ["-o", f"UserKnownHostsFile={target.known_hosts}"] if target.known_hosts else []
        r = proc.run([
            "ssh", "-T", "-i", str(target.identity_path),
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", *kh,
            f"git@{self._host()}",
        ], timeout=20)
        return "successfully authenticated" in (r.stderr + r.stdout).lower()

    def list_deployed(self, target: Target) -> list[str]:
        rows = self._list_remote(target) if self._can_api(target) else None
        if not rows:
            return []
        return [str(r.get("title", "")) for r in rows]

    def remove(self, target: Target) -> bool:
        """Revoke by matching the key *body* (never the title). Returns True if it acted."""
        if not self._can_api(target):
            return False
        want = key_body(target.pubkey_text)
        rows = self._list_remote(target)
        if rows is None or not want:
            return False
        ok = False
        for row in rows:
            if key_body(str(row.get("key", ""))) == want and row.get("id") is not None:
                d = proc.run(
                    ["gh", "api", "--method", "DELETE", f"user/keys/{row['id']}"],
                    env=self._env(target), timeout=30,
                )
                ok = ok or d.returncode == 0
        return ok

    def manage_url(self, target: Target) -> str | None:
        if self.spec and self.spec.resolved_keys_url():
            return self.spec.resolved_keys_url()
        return f"https://{self._host()}/settings/keys"
