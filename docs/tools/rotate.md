# rotate / rollback - zero-downtime key rotation

```sh
sshmgr rotate <key> [--allow-unverified] [--passphrase] [--yes]
sshmgr rollback <key> [--yes]
```

Rotation never leaves a `...-ed25519.new` sibling: the active key keeps its
canonical name throughout, and the outgoing key is archived under the **identical
filename** - so swap-back is a plain move and there's never a name collision.

## The flow (invariant 7)

1. **Stage** a replacement in `profiles/<profile>/.staging/` (never left behind).
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

## Shared keys

For a `shared` profile key the deploy/verify/revoke steps **fan out to every host**
in the profile - one keypair, many targets.

## rollback

`rollback <key>` is the symmetric reverse: it moves the single `/old/` predecessor
back to the canonical name, re-deploys it, and revokes the rotated-in key -
available until the next rotation supersedes it.

`doctor` asserts the ≤1-old invariant (counted per key name).
