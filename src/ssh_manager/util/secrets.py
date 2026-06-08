"""Secret resolution - keep provider tokens out of plaintext ``.env`` if you want.

A token env var (e.g. ``GH_TOKEN``) normally holds the secret directly. To avoid
storing it at rest, set the value to ``cmd:<command>`` and the command is run at
use-time; its stdout (trimmed) is the secret. The command is split with shell
word rules (``shlex``) and run via the argv-only subprocess chokepoint (never
``shell=True``) - so it integrates with any secret manager:

    GH_TOKEN=cmd:op read op://Private/GitHub/token        # 1Password CLI
    GH_TOKEN=cmd:keyring get ssh-manager gh_token              # OS keyring
    GH_TOKEN=cmd:age -d -i ~/.config/ssh-manager/age-identity.txt ~/gh.token.age

A plain value is returned as-is, so this is fully backward compatible.
"""
from __future__ import annotations

import shlex
from functools import lru_cache

from . import proc

_CMD_PREFIX = "cmd:"


@lru_cache(maxsize=128)
def _run_cmd_secret(command: str) -> str | None:
    """Run a ``cmd:`` secret command once and cache its result for the process.

    Memoized because a single provider operation resolves the token several times
    (capability check, env, then the CLI call) - without caching, a slow or
    biometric-prompting secret manager would fire 2-3x per host. A failure / timeout
    / empty output yields ``None`` (the provider degrades to the manual path)."""
    argv = shlex.split(command)
    if not argv:
        return None
    result = proc.run(argv, timeout=20)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def resolve_secret(raw: str | None) -> str | None:
    """Resolve a token value: ``cmd:<command>`` runs the command and returns its
    trimmed stdout (memoized per process); anything else is returned unchanged.
    ``None``/empty -> ``None``."""
    if not raw:
        return None
    if not raw.startswith(_CMD_PREFIX):
        return raw
    return _run_cmd_secret(raw[len(_CMD_PREFIX):])
