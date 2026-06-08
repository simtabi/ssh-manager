"""known_hosts pinning via ssh-keyscan (invariant 10).

Seed ``~/.ssh/known_hosts`` from ``ssh-keyscan``, but show each host key's
fingerprint and require confirmation rather than blind trust-on-first-use. The
service returns scanned keys (data) so the surface can confirm; ``add`` appends
the confirmed lines, deduped, with the right perms.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..platforms.base import Platform
from ..util import fs, proc

KNOWN_HOSTS_MODE = 0o644


@dataclass(frozen=True)
class ScannedKey:
    host: str
    port: int
    keytype: str
    line: str
    fingerprint: str


class KnownHostsService:
    def __init__(self, platform: Platform, ssh_dir: Path) -> None:
        self._platform = platform
        self._ssh = ssh_dir

    def path_for(self, profile: str | None) -> Path:
        """The per-profile trust store (everything under the profile), or the
        top-level file as a fallback for a host not in any profile."""
        if profile is None:
            return self._ssh / "known_hosts"
        return self._ssh / "profiles" / profile / "known_hosts"

    def scan(self, host: str, port: int = 22) -> list[ScannedKey]:
        """ssh-keyscan a host and fingerprint each returned key (no writes)."""
        if not proc.has("ssh-keyscan"):
            return []
        cmd = ["ssh-keyscan", "-T", "5"]
        if port != 22:
            cmd += ["-p", str(port)]
        cmd += ["--", host]                         # -- so a hostile hostname can't be an option
        out = proc.run(cmd, timeout=30).stdout       # bound total wall time, not just per-connect
        keys: list[ScannedKey] = []
        for line in out.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split()
            keytype = parts[1] if len(parts) >= 2 else "?"
            keys.append(ScannedKey(host, port, keytype, line, self._fingerprint(line)))
        return keys

    def ensure(self, profile: str | None = None) -> bool:
        """Create the profile's known_hosts file (empty, correct perms) if absent so
        the path the rendered config references always exists. Returns True if created."""
        path = self.path_for(profile)
        if path.is_file():
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        fs.write_text_atomic(path, "", KNOWN_HOSTS_MODE)
        self._platform.set_perms(path, KNOWN_HOSTS_MODE)
        return True

    def add(self, lines: list[str], profile: str | None = None) -> int:
        """Append confirmed host-key lines to the profile's trust store, deduped,
        atomically. Returns the count added."""
        path = self.path_for(profile)
        existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        seen = set(existing)
        fresh = [ln for ln in lines if ln not in seen]
        if not fresh:
            return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join([*existing, *fresh]).strip() + "\n"
        fs.write_text_atomic(path, body, KNOWN_HOSTS_MODE)
        self._platform.set_perms(path, KNOWN_HOSTS_MODE)
        return len(fresh)

    def _fingerprint(self, line: str) -> str:
        if not proc.has("ssh-keygen"):
            return "?"
        r = proc.run(["ssh-keygen", "-lf", "-"], input_=line)
        parts = r.stdout.split()
        return parts[1] if len(parts) >= 2 and parts[1].startswith("SHA256:") else "?"
