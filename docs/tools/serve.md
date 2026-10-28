# `serve`

`sshmgr serve` opens a read-only web UI for one sshmgr home in a browser on this machine.

## Starting it

```sh
sshmgr serve                 # 127.0.0.1:7822, opens a browser
sshmgr serve --no-open       # print the address only
sshmgr --dev-root ./scratch serve
```

It prints an address like this:

```text
sshmgr web UI: http://127.0.0.1:7822/?token=…
reading /Users/you/.config/ssh-manager (read-only)
press Ctrl-C to stop
```

The token in the address signs the browser in, once. The browser swaps it for a session cookie and
drops it from the address bar. Without the token, every page answers 401.

If port 7822 is taken, `serve` uses the next free port and says which. `--port` pins a port and fails
when that port is taken.

## Pages

| Page | Shows |
|---|---|
| Overview | the rows the `sshmgr` menu prints at the top, each problem with the command that fixes it; counts; keys due for rotation; recent changes |
| Profiles | each profile's category, key scope, key store, and host and key counts |
| Hosts | every host by profile. A host's page shows its manifest entry, its deployments, the block rendered into `~/.ssh/config`, and the host keys pinned for it |
| Keys | every key with its fingerprint and expiry. A key's page shows where the key is deployed and every operation that touched it |
| Snapshots | every snapshot. A snapshot's page diffs it against `~/.ssh` now or against another snapshot |
| History | the [`history`](history.md), filtered the same way. An operation's page shows its events and the manifest before and after |
| Doctor, Audit | the reports `sshmgr doctor` and `sshmgr audit` print |

## What it will not do

- **Change anything.** Every route is a GET. Make changes with the CLI or the menu, then reload the
  page.
- **Hold the lock.** A running server never holds up an sshmgr command.
- **Open a snapshot that holds private keys.** A snapshot written before private keys were left out
  is listed but never opened. `sshmgr snapshots prune --keep 0` removes it.
- **Show private keys.** Pages read public keys, `known_hosts` and config only.
- **Create the history.** A page view reads `log/history.db` if it exists. Only a command that holds
  the lock creates it or imports into it.

## Security

- **Loopback by default.** A non-loopback `--addr` is refused unless you pass `--allow-remote`, and
  even then it serves plain HTTP. An SSH tunnel is better:
  `ssh -L 7822:127.0.0.1:7822 <host>`.
- **Host check.** The server answers only to `127.0.0.1`, `localhost` and `::1` at its port, plus
  any `--allow-host`. That stops a page on another site from rebinding its name to this machine.
- **Session cookie.** `HttpOnly` and `SameSite=Strict`. Every request that could change state is also
  held to the page's own origin and a per-session token.
- **Headers.** Every response sends a strict Content-Security-Policy with no inline script or style,
  plus `nosniff`, `X-Frame-Options: DENY`, `no-referrer` and same-origin COOP and CORP.
- **No network.** The page loads nothing from the network: Tabler, its icons and the page's own script
  are embedded in the binary.

`--token-file <path>` also writes the sign-in address to a file with mode 0600, for scripts.

## Flags

| Flag | Meaning |
|---|---|
| `--addr` | host, or host:port, to listen on (a port here pins it) |
| `--port` | port; pinned when given |
| `--allow-remote` | permit a non-loopback `--addr` |
| `--allow-host` | an extra Host header to accept, such as a proxy's name (repeatable) |
| `--read-only` | serve no route that changes anything. Every route is read-only for now, so this has no effect yet. |
| `--no-open` | do not open a browser |
| `--token-file` | also write the sign-in address to this file |

## Updating Tabler

The embedded Tabler version is pinned in `src/internal/web/assets/vendor/TABLER_VERSION`. Three
targets manage it:

- `make tabler-check` reports a newer release.
- `make tabler-update` moves to the newest release.
- `make tabler-vendor` re-vendors the pinned version.

Each target checks every download against npm's integrity hash, then rewrites the files, the
licences, `MANIFEST.sha256` and `THIRD_PARTY_NOTICES.md` together.

---

[← Docs index](../../README.md#documentation)
