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
| Delete a profile and its key files | Profiles, ticking *and its key files* | `sshmgr profile delete --purge --yes` |
| Move a profile to a category | Profiles | `sshmgr profile edit --category` |
| Add a host, or a VM host | Hosts | `sshmgr host add`, `sshmgr vm add` |
| Add or update hosts from specs | Hosts | `sshmgr host apply --host … --yes` |
| Create a VM host's Docker context | the host's page | `sshmgr vm docker-context` |
| Edit a host's hostname, user, port or tags | the host's page | `sshmgr host edit` |
| Delete a host and its pins | the host's page | `sshmgr host delete --yes` |
| Delete a declared key that no host uses | Keys | `sshmgr key delete --yes` |
| Re-render `~/.ssh/config` | Overview | `sshmgr config render --yes` |
| Reconcile: mint missing keys, record keys on disk, render | Overview | `sshmgr reconcile --yes --no-pin` |
| Mint a profile's or host's missing keys | Keys | `sshmgr keygen <target> --no-pin --yes` |
| Add a key, optionally wired to a host | Keys | `sshmgr key add` |
| Prune old snapshots | Snapshots | `sshmgr snapshots prune --keep` |
| Restore a snapshot | the snapshot's page | `sshmgr snapshots restore <id> --yes` |
| Fix file modes | Doctor | `sshmgr doctor --fix` |
| Write an editable `providers.json` | Doctor | `sshmgr providers --export` |
| Remove stale pins and records, optionally adopting pins first | Doctor | `sshmgr clean --yes [--adopt]` |
| Write an encrypted bundle | Snapshots | `sshmgr bundle [--keep]` |
| Send the desktop alert, if one is due | Audit | `sshmgr audit --notify` |
| Send a test notification | Audit | `sshmgr notify test` |

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

**Files the copy cannot show.** A purge deletes private keys, and a category move carries them to a
new directory. The copy holds them only as placeholders, so the preview lists each one the change
would remove or create, by path, without its contents. That list is bound to the confirmation too.

**Deleting a profile's key files** always writes an encrypted backup of `~/.ssh` and the config
first, as the CLI does, so it needs `SSH_MANAGER_AGE_RECIPIENT` set where `sshmgr serve` runs, and
`age` installed. There is no `--no-key-backup` on the web.

**Changes with effects outside the copy.** Prune and fix list what they would do outside the copied
files: the snapshots they would remove, the paths whose modes they would fix. A bundle, a Docker
context and the notifications act outside the home altogether, so a preview never runs that part;
it lists what confirming will do, and only confirming does it. The confirmation is bound to those
lists too. Prune, bundle, the Docker context and the notifications take no snapshot first, as their
commands take none.

**Restoring a snapshot** previews exactly what it puts back: the copy is restored from the
snapshot, and the page shows the diff against `~/.ssh` now. The confirmation names the snapshot
file. Confirming snapshots `~/.ssh` first, then restores. A snapshot that still holds private keys
is refused here, as its page refuses to open it.

**Exports download.** The hosts page offers the flat `ssh_config` (`sshmgr config export --flat`)
and the Termius CSV (`sshmgr termius export`, with or without git hosts) as downloads. Nothing is
written to the home, so `--read-only` keeps them.

## Jobs

Deploying, rotating and rolling back reach the hosts that use a key, so no copy can preview them.
A key's page offers each as a **job**:

1. **Review.** The page says what the job will do, and the command it is the same as.
2. **Run.** The job starts, and its page shows the output as it comes. It holds the lock until it
   ends, and it is recorded in the history like any other change.

| Job | Where | The same as |
|---|---|---|
| Deploy a key to every host that uses it | the key's page | `sshmgr deploy <profile/key> --yes` |
| Rotate a key | the key's page | `sshmgr rotate <profile/key> --yes` |
| Roll a key back to its predecessor | the key's page | `sshmgr rollback <profile/key> --yes` |

- **One job at a time.** Starting a second while one runs takes you to the one running. No change
  is previewed or made while a job runs.
- **Nothing a job runs can prompt.** `ssh` and `ssh-copy-id` run with stdin closed and
  `BatchMode=yes`, so a target that needs a password fails at once, with a note to deploy it from a
  terminal. A terminal is where the CLI still asks.
- **Rotate asks you to paste a key.** A target that takes the key by hand, such as a panel, pauses
  the job with the new public key shown for copying. Confirm once it is pasted; sshmgr then logs in
  with it to prove it. Rotate writes an encrypted backup first, so it needs
  `SSH_MANAGER_AGE_RECIPIENT`.
- **Cancel** stops a job at its next step, never inside one. A rotate waiting on you is answered no.

Some changes are terminal-only:

- rotating, overwriting a key (`keygen --force`), and passphrases;
- rotating many keys at once, revoking a key from its targets (`--revoke`), and restoring a
  bundle, which needs the encrypted backup's identity;
- pinning host keys (`knownhosts init`, `knownhosts pin`): a scan reaches every host, and trusting
  a key is a decision made per key;
- `key regen-pub`: it needs the private keys, which a preview never copies, and may ask for a
  passphrase;
- `--no-key-backup`.

`--read-only` serves none of the changes in the table above, and the pages show no forms.

## What it will not do

- **Hold the lock while you read.** It holds the lock only while it checks and makes a change you
  confirmed. The `sshmgr` menu now does the same.
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
