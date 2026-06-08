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

```sh
sshmgr validate                     # all keys
sshmgr validate work                # one profile
sshmgr validate work_unc-ed25519    # one key
```

Example: a corrupted `.pub`, a mismatched pair, or loose perms each surface as a
red ✗ with the specific issue, and the command exits non-zero.

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
