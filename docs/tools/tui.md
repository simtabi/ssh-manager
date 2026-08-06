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

It opens with the expiry banner, then the menu:

| Entry | Equivalent verb |
|---|---|
| Browse profiles & hosts | `list`, then `view <alias>` |
| Show rendered config | `config show` |
| Expiry status | `expiry` |
| Audit (deployments + expiry) | `audit` |
| Reconcile (apply manifest) | `reconcile` — dry-run preview first, then asks |
| Pin host keys (known_hosts) | `knownhosts pin` |
| Deploy a key | `deploy <key>` |
| Rotate a key | `rotate <key>` — confirms; destructive |
| Snapshots (list / restore) | `snapshots list`, `snapshots restore` |
| Quit | — |

## Answering it

Anything that is not a listed number cancels rather than selecting: an
out-of-range number, a blank line, a stray keystroke, or a closed input. A menu
that treated an accidental key as a choice would run whichever action happened to
be first.

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
