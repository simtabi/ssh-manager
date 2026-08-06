# Back up, and restore onto a new machine

The only path that recovers **the same keys**. Snapshots do not: they carry no
private key material by design.

Create an age identity and keep it somewhere other than the machine you are
backing up:

```sh
age-keygen -o ~/age-identity.txt        # note the "public key:" line
sshmgr bundle -r age1... -o ~/Backups
```

The bundle holds the private keys, the manifest, the inventory and
`providers.json`. It **never** holds `.env` — that is where provider API tokens
live, and a backup you might copy to another machine is the wrong place for them.
The archive is encrypted before it reaches the disk; there is no plaintext
staging copy in `$TMPDIR`.

On the new machine:

```sh
sshmgr init
sshmgr restore ~/Backups/ssh-manager-*.age -i ~/age-identity.txt
sshmgr validate                          # every pair parses and matches
sshmgr doctor
```

`restore` overlays: a key already on disk that the bundle does not contain — one
minted since the backup — survives. It replaces only what it has a copy of.

> Set `SSH_MANAGER_AGE_RECIPIENT` and `SSH_MANAGER_AGE_IDENTITY_FILE` to skip the
> flags. The recipient is also what lets `keygen --force` write a backup before
> destroying a key, instead of refusing.

Reference: [`bundle`](../tools/bundle.md).

---

[← Docs index](../../README.md#documentation)
