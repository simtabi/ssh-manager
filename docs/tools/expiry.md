# expiry & notifications - "always warn before a key is due"

A raw SSH keypair **does not self-expire** (only OpenSSH *certificates* carry a
hard validity window). So this is a **policy reminder** ssh-manager computes and
surfaces - nothing breaks on the date; it's the cue to rotate.

## How it's computed

From the inventory, per key: `expires_on = created + rotate_after_days`,
`days_remaining`, and a `state`:

- `ok` - outside the warn window
- `due_soon` - within the largest `warn_before_days` threshold (default 30)
- `overdue` - past `expires_on`

`rotate` resets `created`/`expires_on`, clearing the warning. Archived `/old/`
keys are excluded.

## Surfaces (layered - warned whether or not you open the tool)

1. **Inline banner** - every command runs a cheap, **debounced** check first
   (cached for `expiry_check.debounce_hours`, default 24) and prints a `⚠` line to
   stderr for any due/overdue key. Never breaks scripting (stderr, best-effort).
2. **`sshmgr expiry`** - the full table (key, profile, `expires_on`, days, state).
   Also folded into `sshmgr audit`.
3. **Scheduled notifier** - `sshmgr notify install` registers a launchd (macOS) /
   cron (Linux) job running `sshmgr audit --notify`. It emits a **desktop
   notification** and appends to the audit log. Cadence is **weekly** normally,
   **daily** once any key is inside its warn window, with a last-notified debounce.
   `sshmgr notify test` fires a test notification.

All of this is config-driven from `defaults.warn_before_days` and
`defaults.expiry_check` in the manifest (`SSH_MANAGER_SNAPSHOT_RETAIN` and the cadence
caches live in the config-dir, gitignored).

```sh
sshmgr expiry                 # full table
sshmgr audit --notify         # report + cadence-gated desktop alert (what the job runs)
sshmgr notify install         # set up the scheduled notifier
sshmgr notify test            # confirm desktop notifications work
```
