# validate & providers - integrity checks

## `sshmgr validate [key|profile]`

Validates managed keypairs. With no argument it checks **every** managed key;
pass a key name or a profile to scope it. Exits non-zero if any key fails (so it
works in CI / pre-flight).

For each key it checks:

- the **private key** parses and exists;
- the **public key** (`.pub`) parses and isn't malformed (the base64 body must
  decode to a wire-type matching the key type - a base64-looking comment is
  rejected);
- the **pair matches** - the public key is *derived from the private material*
  via `ssh-keygen -y` (the only check that actually proves a keypair; reading
  `ssh-keygen -lf` on a private key would just re-read the `.pub`);
- **permissions** are correct (private `600`, public `644`) - routed through the
  platform, so it's meaningful on macOS/Linux and ACL-aware on Windows.

**Encrypted private keys** are *noted, not failed*: the pair can't be verified
without the passphrase, but the key is valid.

**Keys in 1Password** (`key_store: 1password`) have no private key on disk. For
them validate checks that the item exists in the profile's vault and that its
public key is the `.pub` on disk. It fails a private key *file* found beside
one: the `.pub` makes it look present, but ssh asks the 1Password agent, which
does not hold it. Without `op` the vault check is noted, not failed.

```sh
sshmgr validate                     # all keys
sshmgr validate work                # one profile
sshmgr validate work_hpc-ed25519    # one key
```

Example: a corrupted `.pub`, a mismatched pair, or loose perms each surface as a
red ✗ with the specific issue, and the command exits non-zero.

## `sshmgr key regen-pub [selector ...] [--category <name>] [--all]`

Rebuilds public keys from the key they belong to, when a `.pub` is missing or
wrong: from the private key with `ssh-keygen -y`, or for a profile with
`key_store: 1password` from its vault item. Selectors work as for `rotate`.

| Result | Meaning |
|---|---|
| `unchanged` | the `.pub` already matched its key |
| `created` | the `.pub` was missing |
| `rewritten` | the `.pub` was a different key; redeploy anything set up from it |
| `skipped` | the private key has a passphrase (the command to derive it by hand is printed), or is missing |
| `failed` | the key could not be read |

The old `.pub`'s comment is kept, and the inventory record moves to the
regenerated fingerprint. It never creates or changes a private key: a missing
private key is `reconcile`'s job, a new one `rotate`'s.

```sh
sshmgr key regen-pub --all --dry-run
sshmgr key regen-pub work
```

## `sshmgr providers`

Lists every provider in the active catalog - your `<home>/providers.json` if you
created one, else the shipped default (`providers --export` materializes an
editable copy) - with its `kind`, `category`, the `token_env` it reads, and whether that
credential is **set right now**:

```sh
sshmgr providers
# NAME           KIND          CATEGORY  TOKEN_ENV           CREDENTIAL
# digitalocean   digitalocean  vps       DIGITALOCEAN_TOKEN  ✓ set
# github         github        vcs       GH_TOKEN            - none
# generic-ssh    ssh           server    -                   n/a
```

Use it to confirm which provider integrations are ready before a `deploy` or
`rotate`. See [providers.md](providers.md) and [vps.md](vps.md) for how to add
and configure providers.

---

[← Docs index](../../README.md#documentation)
