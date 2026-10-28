# `history`

`sshmgr history` lists every change sshmgr has made, newest first, from a SQLite database at
`~/.config/ssh-manager/log/history.db`.

## What is recorded

One operation per command that changes something: every command that takes the advisory lock. You
don't need to do anything to turn it on. Read-only commands (`list`, `show`, `doctor` without
`--fix`, `history` itself) record nothing.

Each operation holds:

| Field | What it is |
|---|---|
| `command`, `args` | the command and its arguments. String flags keep their value only when it is a name from the manifest (`--profile`, `--host`, `--key-name`, `--category`, …); any other value is recorded as `<set>`. |
| `source` | `cli`, `tui` (one operation per change chosen from the menu), `web`, or `backfill` |
| `result` | `ok`, `error` (with the message), `aborted` (declined after the lock was taken), or `dry-run` |
| `snapshot` | the `~/.ssh` snapshot the command took, or a `snapshot.failed` event saying why there is none |
| `events` | every `audit.log` event the command raised |
| manifest before and after | stored once by content, so `history show` can diff them |
| user, machine, version | who ran it, where, with which sshmgr |

`audit.log` is still written first and in the same format. The store indexes it. When a write to the
store fails, the command still succeeds and prints one warning, and `sshmgr history` reports how many
`audit.log` events the store is missing.

The store holds no key material. The manifest and inventory carry none, and a test scans every
column the store writes.

## The first run

The first time the store opens, it imports what is already on disk, as operations of source
`backfill`:

- every line of `audit.log` and its rotated `audit.log.1`;
- each key's creation date and each deployment date from `inventory.json`;
- each snapshot, dated from the stamp in its name;
- the current manifest.

The import runs in one transaction and marks itself done in that transaction. If it fails, nothing is
imported, and the next run tries again.

## Listing

```sh
sshmgr history                          # the last 50, newest first
sshmgr history --host gh --since 7d     # one host, the past week
sshmgr history --command host           # every host add, edit, delete and apply
sshmgr history --source tui --limit 0   # everything done from the menu
sshmgr history --json | jq .            # one object per operation, events nested
```

| Flag | Filters on |
|---|---|
| `--host`, `--profile`, `--key` | what the operation was about: from its arguments and its events |
| `--since`, `--until` | the start time: a date (`2026-10-27`), a time (`2026-10-27T14:00:00Z`) or an age (`36h`, `7d`) |
| `--command` | one command (`"host add"`), or every command in a group (`host`) |
| `--source` | `cli`, `tui`, `web` or `backfill` |
| `--limit` | at most this many; `0` for all |

## One operation

```sh
sshmgr history show 3f9a1c2e
```

`history show` prints the operation's details, its events, and a diff of the manifest before and after.
It takes any unique prefix of the operation id, which `history` prints in its last column.

## Turning it off

`SSH_MANAGER_HISTORY=0` records nothing. `audit.log` is written as before.

## Where it lives

`log/history.db` sits beside `audit.log`, with its `-wal` and `-shm` files. `doctor --fix` holds all
three at `0600`. `sshmgr bundle` doesn't include it: the history belongs to one machine, and it
grows. Nothing prunes it yet. An operation is about 0.5 KB, so 10,000 operations come to about 5 MB.

A newer sshmgr may add to the schema. An older binary that finds a newer schema opens the database
read-only and says so. It never migrates the database down.

---

[← Docs index](../../README.md#documentation)
