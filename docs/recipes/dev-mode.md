# Work against a sandbox instead of your real `~/.ssh`

`--dev-root` points the whole tool at a scratch directory, so you can mint keys,
render config and pin hosts without touching the tree you actually use.

```sh
sshmgr --dev-root ./sandbox init
sshmgr --dev-root ./sandbox reconcile
sshmgr --dev-root ./sandbox doctor
```

Or set it once for a shell:

```sh
export SSHMGR_DEV_ROOT=./sandbox
sshmgr reconcile
```

The flag wins over the variable, so a shell left in dev mode cannot redirect a
run that names its own root.

## What it does

One root, split into two fixed subdirectories:

```
sandbox/
├── ssh/      stands in for ~/.ssh - keys, config, known_hosts
└── config/   stands in for the config home - manifest, inventory, snapshots, logs
```

It is deliberately **one** root and not two independent overrides. The config
home has had `$SSH_MANAGER_HOME` for a long time and `~/.ssh` had nothing, so the
only way to get a scratch tree was to move `$HOME` — which also moves the
ssh-agent socket and the launchd session, changing what you are testing. Two
separate knobs would allow something worse: a run with its config redirected and
its keys still going to the real `~/.ssh`, which looks sandboxed right up until
it overwrites a key you use.

Every command announces it, on stderr:

```
sshmgr: dev mode - writing under /path/to/sandbox, not /Users/you/.ssh
```

and the interactive menu leads with it:

```
! DEV MODE  sandboxed under /path/to/sandbox   not your real ~/.ssh
```

## What it refuses

Two actions reach outside any directory, so dev mode declines them rather than
letting a flag that promises "nothing real" do something real:

| Refused | Because |
|---|---|
| `deploy` | uploads a public key to a live account, which is still there after the sandbox is deleted |
| `notify install` | registers a job with launchd, systemd or schtasks — machine-wide, and it outlives the sandbox |

Everything else works normally.

## Roots it will not accept

A sandbox that overlaps the real tree is not a sandbox, and both directions of
overlap are refused:

- **inside** your real `~/.ssh` or config home — it would write to the very tree
  it exists to avoid;
- **containing** either of them (your home directory, or `/`) — a later
  `snapshots restore` or `clean` under that root would walk the real tree.

## Throwing it away

The root is an ordinary directory with nothing registered anywhere, so `rm -rf`
is the whole cleanup.

---

[← Docs index](../../README.md#documentation)
