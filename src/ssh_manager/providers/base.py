"""Provider interface. Each method optional; tool degrades gracefully.

Strategy base for deployment adapters. A provider knows how to install / list /
revoke a *public* key on a target (a server, a VCS account, a panel). Methods are
optional: the base degrades to the manual / web-panel path, so any unknown
service still works ("paste your public key here, record it").
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Target:
    """Everything a provider needs to act on one host (resolved from the manifest)."""

    alias: str
    hostname: str
    user: str
    pubkey_path: Path
    pubkey_text: str
    port: int = 22
    token_env: str | None = None     # per-host credential env var name
    identity_path: Path | None = None  # private key, for verify (login test)
    known_hosts: Path | None = None  # this host's per-profile known_hosts (trust store)

    @property
    def ssh_dest(self) -> str:
        return f"{self.user}@{self.hostname}"


@dataclass
class DeployOutcome:
    method: str                  # ssh-copy-id | github-gh | gitlab-glab | manual | ...
    verified: bool               # True == confirmed on the target; False == needs-redeploy
    detail: str = ""             # human note (e.g. the manage URL for manual steps)
    error: bool = False          # True == an automated deploy was attempted and FAILED
                                 # (distinct from a manual target that still needs a paste)


@dataclass(frozen=True)
class ProviderSpec:
    """One provider INSTANCE (from providers.json) - parameterizes an adapter for a
    specific service, cloud OR enterprise/self-hosted. Two GitLab instances are two
    specs (different ``host``), so the same adapter serves both."""

    name: str
    kind: str = "generic"        # github | gitlab | gitea | bitbucket | web-panel | ssh | ...
    category: str = "generic"    # vcs | panel | server | generic
    host: str | None = None      # web host, e.g. github.com | ghe.corp | gitlab.acme.io
    api_base: str | None = None
    keys_url: str | None = None  # explicit override; else derived from host+kind
    cli: str | None = None       # gh | glab (for automated deploy)
    token_env: str | None = None # default token env for this instance
    rest: dict[str, Any] | None = None  # generic REST config (kind 'rest'); see cloud.GenericRest

    def resolved_keys_url(self) -> str | None:
        return self.keys_url or keys_url_for(self.kind, self.host)


def keys_url_for(kind: str, host: str | None) -> str | None:
    """Best-effort 'add an SSH key' page for a VCS instance (override via keys_url)."""
    template = _KEYS_URL.get(kind)
    if template is not None and "{host}" not in template:
        return template                       # host-independent (e.g. aws-codecommit)
    h = host or _DEFAULT_HOST.get(kind)
    if h is None:
        return None
    return template.format(host=h) if template else f"https://{h}"


_DEFAULT_HOST = {
    "github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org",
    "gitea": "gitea.com", "codeberg": "codeberg.org", "sourcehut": "meta.sr.ht",
}
_KEYS_URL = {
    "github": "https://{host}/settings/keys",
    "gitlab": "https://{host}/-/user_settings/ssh_keys",
    "gitea": "https://{host}/user/settings/keys",
    "codeberg": "https://{host}/user/settings/keys",
    "forgejo": "https://{host}/user/settings/keys",
    "gogs": "https://{host}/user/settings/ssh",
    "bitbucket": "https://{host}/account/settings/ssh-keys/",
    "bitbucket-server": "https://{host}/plugins/servlet/ssh/account/keys",
    "sourcehut": "https://{host}/keys",
    "azure-devops": "https://{host}/_usersSettings/keys",
    "aws-codecommit": "https://console.aws.amazon.com/iam/home#/security_credentials",
}


class Provider:
    name: str = "base"
    category: str = "generic"   # vcs | panel | server | generic - powers `list --type`

    def __init__(self, spec: ProviderSpec | None = None) -> None:
        self.spec = spec
        if spec is not None:
            self.name = spec.name
            self.category = spec.category

    def deploy(self, target: Target) -> DeployOutcome:
        """Default: degrade to a manual step (record it; verified=False)."""
        return self._manual(target)

    def verify(self, target: Target) -> bool:
        """Confirm the (staged) key authenticates on the target (login test).
        Default: unverifiable (manual/web-panel providers return False)."""
        return False

    def list_deployed(self, target: Target) -> list[str]:
        """Public keys/lines currently authorized on the target (for drift/audit)."""
        return []

    def remove(self, target: Target) -> bool:
        """Revoke the public key from the target. Returns True if it acted."""
        return False

    def rename(self, target: Target, new_title: str) -> bool:
        """Rename the deployed key's label (where the provider supports it).
        Returns True if it acted; the base/most providers can't, so False."""
        return False

    def manage_url(self, target: Target) -> str | None:
        return self.spec.resolved_keys_url() if self.spec else None

    # shared helper
    def _manual(self, target: Target) -> DeployOutcome:
        url = self.manage_url(target)
        where = url or f"{target.ssh_dest} (authorized_keys)"
        return DeployOutcome(
            method="manual", verified=False,
            detail=f"paste {target.pubkey_path.name} at {where}",
        )
