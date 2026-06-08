"""GitLab adapter - `glab` CLI; works for gitlab.com AND self-hosted GitLab.

The instance host comes from the ProviderSpec. ``glab`` selects the instance via
the ``GITLAB_HOST`` environment variable (it has no ``--hostname`` flag) and
authenticates with ``GITLAB_TOKEN``. The token is read from this host's
``token_env`` (default ``GLAB_TOKEN``) and injected into glab's child env as
``GITLAB_TOKEN``. No token/CLI -> web-panel/manual.

Key listing/removal go through ``glab api user/keys`` (stable JSON), and removal is
matched by the key *body* - never by title - so rotation can't revoke the wrong
key. Deploy is idempotent (skips a key already present).
"""
from __future__ import annotations

import json
import os

from ..core.authorized_keys import key_body
from ..util import proc
from ..util.secrets import resolve_secret
from .base import DeployOutcome, Provider, Target


class GitLab(Provider):
    name = "gitlab"
    category = "vcs"

    def _host(self) -> str:
        return (self.spec.host if self.spec and self.spec.host else "gitlab.com")

    def _token(self, target: Target) -> str | None:
        var = target.token_env or (self.spec.token_env if self.spec else None) or "GLAB_TOKEN"
        return resolve_secret(os.environ.get(var))

    def _env(self, target: Target) -> dict[str, str] | None:
        token = self._token(target)
        if not token:
            return None
        # glab reads GITLAB_TOKEN / GITLAB_HOST (not GLAB_*); inject them here.
        return {"GITLAB_TOKEN": token, "GITLAB_HOST": self._host()}

    def _can_api(self, target: Target) -> bool:
        return proc.has("glab") and self._token(target) is not None

    def _list_remote(self, target: Target) -> list[dict[str, object]] | None:
        """The account's SSH keys via the REST API. None on failure (so callers
        never mistake an API error for an empty key list)."""
        r = proc.run(["glab", "api", "--paginate", "user/keys"],
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
            return DeployOutcome("gitlab-glab", verified=True, detail="already present")
        title = f"ssh-manager {target.pubkey_path.name}"
        r = proc.run(["glab", "ssh-key", "add", str(target.pubkey_path), "--title", title],
                     env=self._env(target), timeout=30)
        if r.returncode != 0:
            return DeployOutcome("gitlab-glab", verified=False, detail=r.stderr.strip(),
                                 error=True)
        return DeployOutcome("gitlab-glab", verified=True, detail=f"added as '{title}'")

    def verify(self, target: Target) -> bool:
        if not self._can_api(target):
            return False
        want = key_body(target.pubkey_text)
        rows = self._list_remote(target)
        if rows is None or not want:
            return False
        return any(key_body(str(r.get("key", ""))) == want for r in rows)

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
                    ["glab", "api", "--method", "DELETE", f"user/keys/{row['id']}"],
                    env=self._env(target), timeout=30,
                )
                ok = ok or d.returncode == 0
        return ok

    def manage_url(self, target: Target) -> str | None:
        if self.spec and self.spec.resolved_keys_url():
            return self.spec.resolved_keys_url()
        return f"https://{self._host()}/-/user_settings/ssh_keys"
