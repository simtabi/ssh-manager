# `knownhosts` — pin host keys into the trust store

One hashed `~/.ssh/known_hosts`, owner-only, with every line this tool wrote
tagged so it only ever prunes its own.

v1 kept a `known_hosts` per profile. v2 does not: identity isolation comes from
`IdentityFile` plus a per-host `IdentitiesOnly yes`, which is a stronger
guarantee than where the trust store sits, and one store means a host key is
verified once instead of once per profile that uses it. See *Why one inline
config and one `known_hosts`?* in [Architecture](../architecture.md).

The names in the store are **hashed** (`HashKnownHosts`), so the file is not a
readable list of every host you connect to, and it is mode 0600 rather than the
conventional 0644 for the same reason.

## Host keys must be trusted before the first connection

Until a host's key is in `known_hosts`, a **non-interactive**
client - notably `git push`/`git fetch` - fails with `Host key verification
failed` (OpenSSH defaults to `StrictHostKeyChecking ask`). ssh-manager handles this two
ways:

### Auto-pin on reconcile / keygen (default)

After minting keys, `reconcile` and `keygen` **create or update the trust store**
for the hosts they can reach (trust-on-first-use, like ssh's
`accept-new`). This is best-effort and safe:

- it only **adds** a host that has no pin yet - it never overrides an existing
  entry, so a later genuine key change is still rejected (not silently accepted);
- **unreachable / VPN-gated** hosts are skipped (pin them later, see below);
- disable it with `reconcile --no-pin` / `keygen --no-pin`, or globally with
  `SSH_MANAGER_AUTO_PIN=0` (e.g. air-gapped or fully scripted/deterministic runs).

### Initialize trust stores: `knownhosts init`

To set up known_hosts (create the file + pin its reachable hosts) in one go -
handy after `import`, or to repair a store - use `init`. Scopes are combinable:

```sh
sshmgr knownhosts init personal       # pin the hosts in one profile
sshmgr knownhosts init --all          # pin every host in the manifest
sshmgr knownhosts init --all --force  # re-scan already-trusted hosts, add any new keys
```

It takes a profile or `--all`; a bare `knownhosts init` says what it needs rather
than guessing at a scope.

`--force` re-scans hosts that are already trusted and adds any **new** key types
it finds; it does **not** remove a superseded key (ssh-manager never silently accepts a
changed host key - if a host's key genuinely rotated, remove the stale line by
hand or re-pin with `knownhosts pin`).

A `PROFILE` argument scopes the pass to that profile's hosts; `--all` covers every
host in the manifest. Either way the destination is the same single store, so a
host used by two profiles is pinned once — which is also what OpenSSH consults for
any ad-hoc `ssh` or `git` connection that does not match a managed alias.

It ensures the store exists (correct perms, so the path the config
references is never missing), pins each **reachable** host (trust-on-first-use),
prints the fingerprints it pinned for you to review, and reports:
`pinned` / `already-trusted` / `unreachable` / `no-keys`. For a host you want to
verify *before* trusting, use `knownhosts pin` below.

### Fingerprint-verified pin (recommended for sensitive hosts)

`knownhosts pin` shows each key's fingerprint and asks you to confirm - use it
when you want to verify against the host's published fingerprint rather than
trust-on-first-use, or to pin a host auto-pin couldn't reach:

```sh
sshmgr knownhosts pin --all       # review fingerprints, then pin (per profile)
```

So the first-use sequence is **reconcile (auto-pins reachable hosts) -> deploy**,
and for a VPN-gated host: connect the VPN, then `knownhosts pin`. `sshmgr doctor`
lists any reachable manifest host whose key isn't pinned yet, so a failed push is
easy to diagnose.

## `sshmgr knownhosts pin [HOST] [--all]`

Scans a host with `ssh-keyscan`, shows each key's type + SHA256 fingerprint, and
(after you confirm) writes it into the right profile's `known_hosts` (perms 644):

```sh
sshmgr knownhosts pin github.com         # pin one host (grouped under the profile that uses it)
sshmgr knownhosts pin 203.0.113.10 -p 2222
sshmgr knownhosts pin --all              # pin every host in the manifest
sshmgr knownhosts pin --all --yes        # trust scanned keys without prompting (scripted)
```

You're shown the fingerprint for **each** scanned key and asked to trust it -
compare it against the host's published value before saying yes. `--yes`/`-y`
trusts all scanned keys without prompting (for automation).

Because each profile pins independently, the same hostname reached under two
identities (e.g. two GitHub accounts via host aliases) is trusted separately and
can't leak between them.

---

[← Docs index](../../README.md#documentation)
