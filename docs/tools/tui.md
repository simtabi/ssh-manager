# `tui` — interactive terminal UI

A numbered stdin menu over the same services the CLI verbs use, so nothing is
reimplemented and the two cannot drift.

```sh
sshmgr          # on a terminal, this opens the menu
sshmgr tui      # the same thing, explicitly
```

Running the binary with no arguments opens the menu when standard input is a
terminal. With any argument it is a plain CLI, and without a terminal — a pipe, a
script, a CI job — it prints help instead. That fallback matters: a menu reading
from a pipe would take whatever is on it as answers.

## What it is

A plain numbered menu, not a full-screen application. Type a number, press enter.
There are no arrow keys, no alternate screen, and no colour — the binary has one
third-party dependency (`cobra`) and no presentation library, which is what makes
every command's output pipe-safe by default. See *Why is the TUI a plain menu?*
in [Architecture](../architecture.md).

## The banner

It opens with a header describing the session:

```
  sshmgr v3.0.1   darwin/arm64   built 2026-08-06 from d7ea28f

  home      ~/.config/ssh-manager   (providers: shipped default)
  ssh       ~/.ssh
  manifest  5 profiles, 7 hosts, 7 keys
  agent     running, 2 keys loaded
! rendered  drifted from the manifest          sshmgr reconcile
! pins      6 of 7 pinned                      sshmgr knownhosts pin
! perms     1 path with the wrong mode         sshmgr doctor --fix
```

The two paths are the point of it. Both the config home and `~/.ssh` are
environment-overridable, so without them a session pointed at a sandbox and one
pointed at your real tree look identical — and every entry under *Change
`~/.ssh`* rewrites whichever one it is.

A row marked `!` is a problem, and carries the command that resolves it in the
last column, so the report and the remedy are never in two different places. A
first run has no manifest and says so, naming `sshmgr init`.

The banner is redrawn after any action that changes `~/.ssh`, so watching
`drifted` become `in sync` is the confirmation that the action landed.

## The menu

Entries are grouped by consequence, not by frequency — everything above *Change
`~/.ssh`* is safe to pick by accident:

```
  Inspect
   1  Browse profiles & hosts         list
   2  Show the rendered config        config show
   3  Expiry status                   expiry
   4  Audit deployments & expiry      audit

  Change ~/.ssh   (each one asks before it writes)
   5  Reconcile - apply the manifest  reconcile
   6  Pin host keys into known_hosts  knownhosts pin
   7  Deploy a key to its target      deploy
   8  Rotate a key                    rotate

  Recover
   9  Snapshots - list and restore    snapshots

   q  Quit
```

The right-hand column is the CLI verb that does the same thing, and it is also
an accepted answer — typing what is on screen is never a dead end. So `5`,
`reconcile`, and the full label all select the same entry.

## Answering it

A number, a command name, or `q`. Anything else re-prompts rather than selecting:
an out-of-range number, a misspelled verb, a stray keystroke. A menu that treated
an accidental key as a choice would run whichever action happened to be first,
and one that exited on a typo would cost you the session for a slip. A bare Enter
redraws the menu without comment; a closed input ends the session.

Destructive actions — rotate, snapshot restore — confirm before proceeding, and
`~/.ssh` is snapshotted before any mutation regardless, by the same guard every
CLI verb passes through.

It needs an interactive terminal. In a script or a pipe it prints a hint and
exits; use the CLI verbs there.

## Design note

Interaction goes through a small `prompter` seam: production reads the command's
own input stream, tests inject a scripted fake. So the whole navigation loop —
including that destructive actions require confirmation — is exercised without a
TTY.

> The production prompter read `os.Stdin` directly until v2.1, which meant it
> ignored a redirected input and could only ever be driven by a real terminal.
> Every test injected the fake, so the code a user actually meets was the one
> piece of the TUI never exercised. It reads `c.InOrStdin()` now, like every
> other prompt in the tool.

---

[← Docs index](../../README.md#documentation)
