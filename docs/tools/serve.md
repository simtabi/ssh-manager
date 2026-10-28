# `serve`

`sshmgr serve` opens a web UI for one sshmgr home in a browser on this machine. It shows everything,
and makes the everyday manifest changes, each previewed before it is made.

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

## Changes

These changes can be made from the pages:

| Change | Where | The same as |
|---|---|---|
| Add a profile | Profiles | `sshmgr profile add` |
| Change a profile's key scope | Profiles | `sshmgr profile edit --key-scope --key-name` |
| Delete a profile | Profiles | `sshmgr profile delete --yes` |
| Add a host, or a VM host | Hosts | `sshmgr host add`, `sshmgr vm add` |
| Edit a host's hostname, user, port or tags | the host's page | `sshmgr host edit` |
| Delete a host and its pins | the host's page | `sshmgr host delete --yes` |
| Delete a declared key that no host uses | Keys | `sshmgr key delete --yes` |
| Re-render `~/.ssh/config` | Overview | `sshmgr config render --yes` |
| Reconcile: mint missing keys, record keys on disk, render | Overview | `sshmgr reconcile --yes --no-pin` |
| Mint a profile's or host's missing keys | Keys | `sshmgr keygen <target> --no-pin --yes` |
| Add a key, optionally wired to a host | Keys | `sshmgr key add` |
| Prune old snapshots | Snapshots | `sshmgr snapshots prune --keep` |
| Fix file modes | Doctor | `sshmgr doctor --fix` |
| Write an editable `providers.json` | Doctor | `sshmgr providers --export` |

Each change takes two steps:

1. **Preview.** The change runs for real against a private, throwaway copy of the home. The copy
   holds the config files, plus the files from `~/.ssh` that a snapshot may hold: config,
   `known_hosts` and public keys. No private key is copied. The page shows the command line it
   stands for, what sshmgr would say, and a diff of every file the change would write.
2. **Confirm.** sshmgr takes the lock, then previews the change again. If the new preview differs
   from the one you saw, the change isn't made: someone else may have changed the home since
   (a CLI command, the menu, another tab). The page shows the new preview to confirm instead.
   Otherwise sshmgr snapshots `~/.ssh`, makes the change, releases the lock, and links to the
   change in the [`history`](history.md), where it shows with source `web`.

The lock is held only while a change is checked and made, never while you read a preview.

**Where the copy has no file, a placeholder stands in.** A private key's place in the copy holds an
empty placeholder file. It tells a command the key exists, so the key is never minted again, but it
holds nothing of the key. Copied files keep their modification times.

**Changes that mint a key.** A preview of `reconcile`, `keygen` or `key add` mints throwaway keys in
the copy, and the page says so. Confirming mints new keys, so their fingerprints differ from the
preview's; everything else comes out as shown. These changes never overwrite a key that exists,
never take a passphrase, and never pin hosts, which needs the network. They're refused for a profile
kept in 1Password: a preview mints for real, and in a vault that would leave an item behind.

**Changes with effects outside the copy.** Prune and fix list what they would do outside the copied
files: the snapshots they would remove, the paths whose modes they would fix. The confirmation is
bound to those lists too. Prune takes no snapshot of its own first, because one more snapshot would
push another out.

Some changes are terminal-only:

- rotating, overwriting a key (`keygen --force`), and passphrases;
- `--purge`: it deletes private keys, which a preview never copies;
- moving a profile to a category: it moves key directories;
- pinning host keys, `host apply`, `key regen-pub`, `clean`, the exports, `bundle` and `vm docker-context`.

`--read-only` serves none of these changes, and the pages show no forms.

## What it will not do

- **Hold the lock while you read.** It holds the lock only while it checks and makes a change you
  confirmed.
- **Open a snapshot that holds private keys.** A snapshot written before private keys were left out
  is listed but never opened. `sshmgr snapshots prune --keep 0` removes it.
- **Show private keys.** Pages read public keys, `known_hosts` and config only.
- **Create the history from a page view.** A page reads `log/history.db` if it exists. Only a change
  creates the database or imports into it, and only while it holds the lock.

## Security

- **Loopback by default.** A non-loopback `--addr` is refused unless you pass `--allow-remote`, and
  even then it serves plain HTTP. An SSH tunnel is better:
  `ssh -L 7822:127.0.0.1:7822 <host>`.
- **Host check.** The server answers only to `127.0.0.1`, `localhost` and `::1` at its port, plus
  any `--allow-host`. That stops a page on another site from rebinding its name to this machine.
- **Session cookie.** `HttpOnly` and `SameSite=Strict`. Every change is also held to the page's own
  origin and a per-session form token.
- **Forms take names, never paths.** Profile, host and key names must be letters, digits, `.`, `_`
  and `-`. A hostname or user with a control character in it is refused, so a form cannot smuggle a
  line into `~/.ssh/config`.
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
| `--read-only` | serve no route that changes anything, and show no form |
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
