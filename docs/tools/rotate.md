# rotate / rollback - zero-downtime key rotation

```sh
sshmgr rotate <key> [--allow-unverified] [--passphrase] [--yes]
sshmgr rotate [<key>|<profile>|<alias> ...] [--category <name>] [--all] [--dry-run]
sshmgr rollback <key> [--yes]
```

Rotation never leaves a `...-ed25519.new` sibling: the active key keeps its
canonical name throughout, and the outgoing key is archived under the **identical
filename** - so swap-back is a plain move and there's never a name collision.

## The flow (invariant 7)

1. **Stage** a replacement in the profile's `.staging/` (never left behind).
2. **Deploy** the staged public key to every target (the current key is still
   active and authorized - nothing breaks here).
3. **Verify** login with the staged key on each target (`ssh ... true`; `ssh -T`
   for GitHub).
4. **Commit - only after all verify:**
   - purge any existing predecessor in `/old/` (enforces **≤1 old per key**),
   - move the current `<name>(.pub)` → `old/<name>(.pub)` (same filename),
   - promote the staged key to the canonical name,
   - **revoke** the old public key from each target,
   - reset the inventory (new fingerprint, fresh `created`/`expires_on`) + audit.
5. **On any failure before commit:** the staged key is discarded and the active
   key and its files are untouched - true zero-downtime.

`~/.ssh` is snapshotted before the rotation starts (the mutation guard), so the
whole operation is reversible with `sshmgr snapshots restore` as well.

## Verification & manual targets

Each target must verify before commit. Automated providers (generic SSH, GitHub
with a token) verify by logging in / `ssh -T`. A **manual / web-panel** target
(e.g. ploi) can't auto-verify, so rotation **aborts by default** - finish the
paste in the panel and re-run with `--allow-unverified` to accept it.

## Rotating a batch

`rotate` takes any number of keys, profiles or host aliases, every key in a
category (`--category orgs`), or every key (`--all`):

```sh
sshmgr rotate --all --dry-run          # list what would rotate
sshmgr rotate --category clients
sshmgr rotate simtabi imanimanyara/imanimanyara_github-ed25519
```

A batch asks once, writes one encrypted backup and one snapshot, then rotates
each key on its own with the flow above. A key that fails (an unreachable host,
a target that will not verify) is left exactly as it was, and the rest still
rotate; the command exits non-zero and names the keys it left. The inventory is
saved after every committed key, so an interrupted batch keeps what it
finished. A key no host uses is skipped: there is nothing to deploy it to.

A selector that matches nothing is an error, so a typo never runs as an empty
batch, and `--all` cannot be combined with other selectors.

## Shared keys

For a `shared` profile key the deploy/verify/revoke steps **fan out to every host**
in the profile - one keypair, many targets.

## rollback

`rollback <key>` is the symmetric reverse: it moves the single `/old/` predecessor
back to the canonical name, re-deploys it, and revokes the rotated-in key -
available until the next rotation supersedes it.

`doctor` asserts the ≤1-old invariant (counted per key name).

## Keys kept in 1Password

For a profile with `key_store: 1password` the flow is the same, with the vault
standing in for the private key files:

1. **Stage** a new SSH Key item titled `<key>.staged` in the profile's vault
   (a leftover from a crashed rotation is archived first); its public half goes
   to `.staging/`.
2. **Deploy** and **verify** as above. A verify login uses the staged `.pub`
   through the 1Password agent, so nothing private is read.
3. **Commit:** any earlier `<key>.old` item goes to the vault's Archive (one
   predecessor, as on disk), the live item is retitled `<key>.old`, the staged
   item takes `<key>`, and the public keys move as files do. A failed step puts
   back what had moved.

`rollback` retitles `<key>.old` back to `<key>` and archives the rotated-in
item. sshmgr archives items and never deletes them, so every one is still
recoverable from 1Password's Archive.

Rotating a key whose profile has just been switched to `1password` moves it
into the vault: the outgoing key file pair is archived to `old/`, and the new
key exists only as an item. A rollback across that move is refused, because its
predecessor is a key file; set `key_store` back to `file` to roll back.

## A GitHub machine user

A key on a GitHub account is deployed, verified and revoked through that
account's API, with the token named by the host's `token_env`. When both the
API and an ssh login are available, verify also checks that GitHub greets the
key as the account the token belongs to, so a token for the wrong account
fails the rotation instead of committing a key the alias cannot push with. See
[Use a GitHub machine user](../recipes/github-machine-user.md).

---

[← Docs index](../../README.md#documentation)
