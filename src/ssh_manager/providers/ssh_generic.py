"""Generic SSH adapter - ssh-copy-id / authorized_keys (any reachable server).

The universal fallback (resolution order #2): works on any server you
can already reach. ``deploy`` uses ``ssh-copy-id`` (idempotent); ``remove`` does
the whole read-modify-write in ONE remote invocation under an ``flock`` advisory
lock - it backs up ``authorized_keys`` first, removes the key by base64 body,
refuses to leave the file with no key lines (lockout guard), and writes atomically
(temp + ``mv``). Doing it in a single locked remote script avoids the race two
separate read-then-write ssh calls would have. Hardening adapted from a standalone
VPS key tool.
"""
from __future__ import annotations

from ..core.authorized_keys import key_body, key_lines
from ..util import proc
from .base import DeployOutcome, Provider, Target

_HINT = "install OpenSSH (macOS ships it; else: brew install openssh)"

# Remote read-modify-write of authorized_keys, run as one ssh command under flock.
# Exit codes: 0 removed; 2 key not present; 3 lockout guard tripped (would leave no
# key lines); 4 lock/setup failure. {body} is a base64 body (single-quoted, escaped).
_REMOVE_SCRIPT = r"""set -eu
AK="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
[ -f "$AK" ] || : > "$AK"
exec 9>"$HOME/.ssh/.ssh-manager.lock" || exit 4
if command -v flock >/dev/null 2>&1; then flock 9 || exit 4; fi
BODY='{body}'
grep -qF -- "$BODY" "$AK" || exit 2
TMP="$(mktemp "$AK.ssh-manager.XXXXXX")" || exit 4
grep -vF -- "$BODY" "$AK" > "$TMP" || true
# Lockout guard: refuse to leave authorized_keys with no real (non-comment) line.
if ! grep -Eq '^[[:space:]]*[^[:space:]#]' "$TMP"; then rm -f "$TMP"; exit 3; fi
cp -p "$AK" "$AK.ssh-manager.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
chmod 600 "$TMP"
mv "$TMP" "$AK"
"""


class GenericSSH(Provider):
    name = "generic-ssh"
    category = "server"

    @staticmethod
    def _known_hosts_opts(target: Target) -> list[str]:
        # Use this host's per-profile trust store, so deploy/verify read+populate the
        # SAME known_hosts that `ssh <alias>` uses (per-profile isolation) - not the
        # default ~/.ssh/known_hosts. accept-new (set by callers) then lands a
        # first-seen host key in the right store.
        return ["-o", f"UserKnownHostsFile={target.known_hosts}"] if target.known_hosts else []

    def _ssh_base(self, target: Target) -> list[str]:
        # ConnectTimeout so an unreachable host fails fast instead of hanging.
        base = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10", *self._known_hosts_opts(target)]
        if target.port != 22:
            base += ["-p", str(target.port)]
        return base

    def deploy(self, target: Target) -> DeployOutcome:
        proc.require("ssh-copy-id", _HINT)
        # -o ConnectTimeout so an unreachable host fails fast instead of hanging
        # on TCP connect (ssh-copy-id forwards -o options to ssh).
        cmd = ["ssh-copy-id", "-o", "ConnectTimeout=10", *self._known_hosts_opts(target),
               "-i", str(target.pubkey_path)]
        if target.port != 22:
            cmd += ["-p", str(target.port)]
        cmd.append(target.ssh_dest)
        # Interactive: ssh-copy-id may prompt for a password (no existing key yet).
        # Bounded so a wedged connection (e.g. VPN-gated host on :443) can't hang.
        code = proc.run_interactive(cmd, timeout=120)
        if code != 0:
            return DeployOutcome(method="ssh-copy-id", verified=False,
                                 detail=f"ssh-copy-id exited {code}", error=True)
        return DeployOutcome(method="ssh-copy-id", verified=True,
                             detail="authorized_keys updated")

    def verify(self, target: Target) -> bool:
        if target.identity_path is None:
            return False
        cmd = [
            "ssh", "-i", str(target.identity_path),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new", *self._known_hosts_opts(target),
        ]
        if target.port != 22:
            cmd += ["-p", str(target.port)]
        cmd += [target.ssh_dest, "true"]
        return proc.run(cmd, timeout=20).returncode == 0

    def list_deployed(self, target: Target) -> list[str]:
        return key_lines(self._read_authorized_keys(target) or "")

    def remove(self, target: Target) -> bool:
        """Revoke the key (best-effort, with safety rails). Returns True only if it
        actually removed the key. The whole read-modify-write happens in one remote
        script under flock, so it can't race another writer; rc!=0 (key absent,
        lockout guard, lock failure, or host unreachable) means it did not act."""
        body = key_body(target.pubkey_text)
        if not body:
            return False
        safe_body = body.replace("'", "'\\''")
        script = _REMOVE_SCRIPT.replace("{body}", safe_body)
        cmd = [*self._ssh_base(target), target.ssh_dest, script]
        return proc.run(cmd, timeout=30).returncode == 0

    # transport
    def _read_authorized_keys(self, target: Target) -> str | None:
        # The remote `|| true` makes a missing file a clean empty read (rc 0); a
        # non-zero rc therefore means ssh itself failed (unreachable/auth) - None,
        # distinct from a genuinely empty authorized_keys ("").
        cmd = [*self._ssh_base(target), target.ssh_dest,
               "cat ~/.ssh/authorized_keys 2>/dev/null || true"]
        r = proc.run(cmd, timeout=20)
        return r.stdout if r.returncode == 0 else None


# re-export for callers that match keys (e.g. cloud adapters)
__all__ = ["GenericSSH", "key_body"]
