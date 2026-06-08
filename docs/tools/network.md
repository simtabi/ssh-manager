# net - connection status & VPN awareness

Some hosts are only reachable over a VPN (a campus/corporate git server, a private
VPS, a host on an HTTPS-style port like `:443`). Without the VPN those hosts don't
just fail - a naive `ssh` can **hang** on the banner exchange. ssh-manager makes every
network action reachability-aware so it fails fast with an actionable message
instead of hanging, and gives you a status indicator you can check first.

## Mark a host as VPN-gated

Add `requires_vpn` (and optionally `vpn_name`) to the host in the manifest:

```json
{"alias": "unc", "hostname": "sc.its.unc.edu", "user": "uncgit", "port": 443,
 "key_name": "work_unc-ed25519",
 "requires_vpn": true, "vpn_name": "UNC VPN", "vpn_url": "https://vpn.unc.edu"}
```

`view <alias>` then shows a reminder, and any unreachable network action names the
VPN (and links its `vpn_url` if set).

## `sshmgr net [selector]`

Shows the connection status of every host (filter by alias, profile, or key), plus
a VPN/tunnel indicator:

```sh
sshmgr net
# PROFILE  HOST        ADDRESS              STATUS     NOTE
# work     unc         sc.its.unc.edu:443   ○ offline  needs VPN (UNC VPN)
# personal github.com  github.com:22        ● online
# ...
# VPN/tunnel interface: detected
```

Exit code is non-zero if a `requires_vpn` host is unreachable, so it works as a
pre-flight gate in scripts. The check is a fast TCP probe; it never changes
anything.

## Fail-fast on every network action

`deploy` and `rotate` run a bounded reachability probe before touching the network:

- **Unreachable host** -> the action stops immediately with
  `<host>:<port> unreachable - this host requires a VPN (<name>); connect it and retry`
  (for a `requires_vpn` host) or a generic "check your network connection" message.
  Nothing is staged or changed.
- The probe is **SSH-level**: a VPN-gated host that accepts the TCP connection on
  `:443` but never speaks SSH is detected as unreachable (a plain `ssh` would hang
  there - `ConnectTimeout` only covers the TCP connect, not the banner).
- As a backstop, every underlying `ssh` / `ssh-copy-id` call is bounded by a hard
  timeout, so no network operation can hang indefinitely.

So if you forget the VPN, `sshmgr rotate work_unc-ed25519` returns in a few
seconds with *"cannot rotate - ... requires a VPN (UNC VPN); connect it and retry"*
rather than wedging your terminal.

See also [deploy](deploy.md), [rotate](rotate.md), [vps](vps.md).
