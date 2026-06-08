# tui - interactive terminal UI

```sh
sshmgr tui
```

An arrow-key menu (rich + questionary) over the **same Facade** the CLI uses - no
behaviour is reimplemented, so the TUI and CLI stay in lockstep. It opens with the
expiry banner, then a menu:

- **Browse profiles & hosts** - pick a profile, see its hosts + key/deploy status,
  drill into a host for its resolved config + fingerprint + deployments.
- **Show rendered config** - the full managed `~/.ssh/config`.
- **Expiry status** / **Audit** - the same tables as `sshmgr expiry` / `audit`.
- **Reconcile** - shows a dry-run preview first, then asks before applying.
- **Deploy a key** - pick a key, deploy via its provider.
- **Rotate a key** - pick a key; **confirms** before the (destructive) rotation.
- **Snapshots** - list and restore a local `~/.ssh` backup (with confirmation).

Destructive actions (rotate, snapshot restore) always confirm first; `~/.ssh` is
snapshotted before any mutation regardless (the Facade mutation guard).

It needs an interactive terminal - in a script or pipe it prints a hint and exits;
use the CLI verbs there.

## Design note (testability)

Interaction goes through a small `Prompter` seam: production wraps `questionary`,
tests inject a scripted fake. So the entire navigation loop - including that
destructive actions require confirmation - is unit-tested without a TTY.
