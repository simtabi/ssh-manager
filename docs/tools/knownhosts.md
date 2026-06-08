# knownhosts - pin host keys per profile

ssh-manager keeps a **per-profile** `known_hosts` (`~/.ssh/profiles/<profile>/known_hosts`,
referenced by each host's `UserKnownHostsFile`), so trust is scoped to the
identity that uses it - no shared, ever-growing global trust store, and no
cross-profile bleed.

## Host keys must be trusted before the first connection

Until a host's key is in its per-profile `known_hosts`, a **non-interactive**
client - notably `git push`/`git fetch` - fails with `Host key verification
failed` (OpenSSH defaults to `StrictHostKeyChecking ask`). ssh-manager handles this two
ways:

### Auto-pin on reconcile / keygen (default)

After minting keys, `reconcile` and `keygen` **create/update each profile's
`known_hosts`** for the hosts they can reach (trust-on-first-use, like ssh's
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
sshmgr knownhosts init personal       # one profile's store
sshmgr knownhosts init --all          # every profile's store
sshmgr knownhosts init --user         # the per-user ~/.ssh/known_hosts (all hosts)
sshmgr knownhosts init --all --user   # both: per-profile stores + the user store
sshmgr knownhosts init --all --force  # re-scan already-trusted hosts, add any new keys
```

`--force` re-scans hosts that are already trusted and adds any **new** key types
it finds; it does **not** remove a superseded key (ssh-manager never silently accepts a
changed host key - if a host's key genuinely rotated, remove the stale line by
hand or re-pin with `knownhosts pin`).

- **Per profile** (`PROFILE` / `--all`) writes `~/.ssh/profiles/<p>/known_hosts` -
  the store each managed alias actually uses (`UserKnownHostsFile`). Trust stays
  per-profile: one identity never trusts another's host keys.
- **Per user** (`--user`) writes the conventional top-level `~/.ssh/known_hosts`,
  which OpenSSH consults for any **ad-hoc** ssh/git connection that doesn't match a
  managed profile alias. Every manifest host is aggregated there once (a host used
  by two profiles is pinned a single time).

It ensures each target file exists (correct perms, so the path the config
references is never missing), pins each **reachable** host (trust-on-first-use),
prints the fingerprints it pinned for you to review, and reports per store:
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
