# bundle / restore - encrypted backup & migration

```sh
sshmgr bundle [--recipient age1...] [--output DIR]
sshmgr restore <bundle.age> [--identity age-identity.txt]
```

Uses **age** (X25519 + ChaCha20-Poly1305) - modern, single-binary, far simpler
than GPG. Install it first: `brew install age` (macOS) / `apt install age` (Linux).

## What's in a bundle

`bundle` tars and age-encrypts:

- the **private keys** under `~/.ssh/profiles/**` (excluding `.staging/`)
- `manifest.json`, `inventory.json`, `providers.json`

...into a single `ssh-manager-<stamp>.age`, alongside two sidecars:

- `*.age.sha256` - checksum (verified before any restore)
- `*.age.contents` - plaintext list of filenames

Without `--output`, bundles are written to `<home>/dist/` (e.g.
`~/.config/ssh-manager/dist/`), owner-only (0700). Pass `--output DIR` to write
elsewhere (e.g. an external drive).

**`.env` is deliberately excluded** - it holds the age recipient/identity refs
that unlock the bundle, so bundling it would be circular. Back `.env` up
separately in your password manager.

## Recipient (where the decryption identity lives)

Set the recipient via `--recipient` or `$SSH_MANAGER_AGE_RECIPIENT`. On restore, the
decryption identity comes from `--identity` or `$SSH_MANAGER_AGE_IDENTITY_FILE` (a path
to an age identity file). Where you keep that identity is up to you:

1. **Password manager** - store the age identity in 1Password/Bitwarden and write
   it to a file (e.g. `op read ... > id.txt`) before pointing `--identity` at it.
2. **Hardware key** - `age-plugin-yubikey`, so decryption needs the physical
   device + touch.

age has **no revocation** - rotate a bundle by re-encrypting to a new recipient
and destroying the old.

## restore = the same keys (contrast with reconcile)

| | source | brings back |
|---|---|---|
| **`restore`** | the encrypted bundle | the **same** keys (same fingerprint) - true recovery |
| **`reconcile`** | the manifest only | rebuilds structure + **mints new** keys for any missing |

`restore` snapshots `~/.ssh` first (reversible), decrypts, lays the keys back
down, re-asserts perms (700/600/644), and re-renders the config from the restored
manifest so `~/.ssh` is immediately usable. Then `sshmgr load <profile>` to add
keys to the agent.

```sh
export SSH_MANAGER_AGE_RECIPIENT=age1ql3z7hjy54pw3hyww5ayyfg7z...
sshmgr bundle -o ~/Backups            # writes ~/Backups/ssh-manager-<stamp>.age (+ sidecars)
# ... new machine ...
sshmgr restore ~/Backups/ssh-manager-<stamp>.age -i age-identity.txt
```
