"""Network reachability + VPN status for host-targeting actions.

Network actions (deploy, rotate, verify, knownhosts pin) can hang or fail when a
host is unreachable - often because it sits behind a corporate/campus VPN that
isn't connected (e.g. a university git host on port 443). This module gives a
fast, bounded reachability check and a best-effort VPN indicator so those actions
fail fast with an actionable message instead of hanging, and so every
network-related command can show a connection-status line.

stdlib only (``socket``); no extra dependency.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

# Interface-name prefixes that indicate a tunnel/VPN. Heuristic and best-effort:
# the reliable signal is reachability to the actual host, not interface names.
_VPN_PREFIXES = ("wg", "tun", "tap", "ppp", "ipsec", "nordlynx", "proton",
                 "tailscale", "ts", "gpd", "ovpn")


_UNREACHABLE_MARKERS = (
    "connection refused", "connection timed out", "operation timed out",
    "could not resolve", "no route to host", "network is unreachable",
    "timed out after", "host is down", "connection reset",
    "connection closed by", "no address associated with hostname",
)


def tcp_reachable(host: str, port: int, *, timeout: float = 4.0) -> bool:
    """True if a TCP connection to ``(host, port)`` opens within ``timeout`` seconds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_reachable(host: str, port: int, *, timeout: float = 10.0) -> bool:
    """True if the SSH layer on ``host:port`` actually responds within ``timeout``.

    Stronger than :func:`tcp_reachable`: a VPN-gated host on an HTTPS-style port
    (e.g. ``:443``) often *accepts the TCP connection* but never completes the SSH
    banner exchange - ``ConnectTimeout`` doesn't cover the banner, so a plain ssh
    would hang. This runs a bounded ``ssh ... true`` probe and treats a live server
    (even one that rejects auth) as reachable, a hang/refusal as not.
    """
    from . import proc
    if not proc.has("ssh"):
        return tcp_reachable(host, port, timeout=timeout)
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={max(1, int(timeout))}",
           "-o", "StrictHostKeyChecking=no", "-p", str(port), "--", host, "true"]
    err = (proc.run(cmd, timeout=timeout + 5).stderr or "").lower()
    return not any(m in err for m in _UNREACHABLE_MARKERS)


def vpn_interfaces() -> list[str]:
    """Best-effort list of tunnel/VPN-like network interfaces currently present."""
    try:
        names = [name for _idx, name in socket.if_nameindex()]
    except (OSError, AttributeError):   # if_nameindex missing on some platforms
        return []
    out = [n for n in names if any(n.startswith(p) for p in _VPN_PREFIXES)]
    # macOS uses utunN for VPNs; utun0-2 are usually system services, so only a
    # higher-numbered utun is a meaningful hint.
    out += [n for n in names if n.startswith("utun") and n[4:].isdigit() and int(n[4:]) >= 3]
    return sorted(set(out))


def vpn_active() -> bool | None:
    """Heuristic: is a VPN/tunnel interface present? ``None`` when undeterminable.

    A hint only - many VPNs and OSes vary. Reachability to the host is the truth.
    """
    try:
        socket.if_nameindex()
    except (OSError, AttributeError):
        return None
    return bool(vpn_interfaces())


@dataclass(frozen=True)
class NetStatus:
    """Reachability of one host:port, with a VPN-aware human message."""

    host: str
    port: int
    reachable: bool
    requires_vpn: bool = False
    vpn_name: str | None = None
    vpn_url: str | None = None
    vpn: bool | None = None

    @property
    def icon(self) -> str:
        return "online" if self.reachable else "offline"

    @property
    def message(self) -> str:
        where = f"{self.host}:{self.port}"
        if self.reachable:
            return f"{where} reachable"
        if self.requires_vpn:
            named = f" ({self.vpn_name})" if self.vpn_name else ""
            at = f" at {self.vpn_url}" if self.vpn_url else ""
            tail = "" if self.vpn else "; no active VPN/tunnel detected"
            return (f"{where} unreachable - this host requires a VPN{named}; "
                    f"connect it{at} and retry{tail}")
        hint = "" if self.vpn else " (or a VPN, if this host needs one)"
        return f"{where} unreachable - check your network connection{hint}"


def check(host: str, port: int, *, requires_vpn: bool = False,
          vpn_name: str | None = None, vpn_url: str | None = None,
          timeout: float = 4.0, ssh: bool = False) -> NetStatus:
    """Reachability + VPN status for one host:port. ``ssh=True`` uses the bounded
    SSH-banner probe (for deploy/rotate); the default TCP probe is faster (status)."""
    reach = (ssh_reachable(host, port, timeout=timeout) if ssh
             else tcp_reachable(host, port, timeout=timeout))
    return NetStatus(
        host=host, port=port, reachable=reach, requires_vpn=requires_vpn,
        vpn_name=vpn_name, vpn_url=vpn_url, vpn=vpn_active(),
    )
