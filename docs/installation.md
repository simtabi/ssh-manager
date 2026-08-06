# Installation

How to get `sshmgr` onto a machine, and where it keeps its state once it is there.

## Requirements

`sshmgr` is a single static binary. There is no runtime to install and no
interpreter to keep current.

- OpenSSH: `ssh`, `ssh-keygen`, `ssh-add`, `ssh-keyscan` (hard dependencies).
  `ssh-copy-id` is used when present; Microsoft's OpenSSH port does not ship it,
  so deployment falls back to plain `ssh` there.
- Optional, each degrading to a manual path when absent: `age` and `age-keygen`
  (encrypted bundles), `gh` and `glab` (VCS key deployment), `age-plugin-yubikey`.

macOS, Linux and Windows are all first-class, each validated on its own CI runner.

## Install

From a release binary:

```sh
curl -fsSL https://opensource.simtabi.com/install/ssh-manager | bash
sshmgr doctor           # verify deps, perms, agent, known_hosts, drift
```

On Windows:

```powershell
irm https://opensource.simtabi.com/install/ssh-manager.ps1 | iex
```

With the Go toolchain:

```sh
go install github.com/simtabi/ssh-manager/src/v3/cmd/sshmgr@latest
```

Both segments after the repository name are load-bearing. `src` is the
subdirectory the Go module lives in, and `v3` is the major version - Go requires
that suffix from v2 onward. Dropping either gives a module path that does not
exist, and the error names a version rather than a path, so it reads as a
missing release:

```
go: ...found (v0.1.0), but does not contain package .../cmd/sshmgr
```

Or download the binary for your platform from
[Releases](https://github.com/simtabi/ssh-manager/releases) and put it on `PATH`.
Every artifact is checksummed and carries a build-provenance attestation
(`gh attestation verify <file> --repo simtabi/ssh-manager`).

## From a clone

```sh
git clone https://github.com/simtabi/ssh-manager && cd ssh-manager
make build                # -> build/sshmgr
./build/sshmgr doctor
```

`make` is the development front door: `make check` runs the same gate as CI
(gofmt, build, vet, tests) plus lint. There is no bootstrap step.

The `.env` and the rest of the per-user home are created by `sshmgr init`, which
seeds `.env` from the shipped `.env-example` at mode `0600`.

## The per-user home (OS-standard config dir)

All of a user's ssh-manager state lives in **one** per-user home - a single `ssh-manager`
folder in the OS-standard config location:

| OS | Default home |
|----|--------------|
| Linux / macOS | `$XDG_CONFIG_HOME/ssh-manager` if set, else `~/.config/ssh-manager` |
| Windows | `%APPDATA%\ssh-manager` |

```
<home>/                             # e.g. ~/.config/ssh-manager
├── manifest.json  inventory.json   # manifest is the source of truth
├── providers.json                  # OPTIONAL - else the shipped default catalog is used
├── .env  age-identity.txt          # secrets (0600)
├── log/audit.log                   # accountability log
├── snapshots/                      # reversible ~/.ssh backups
├── dist/                           # exported encrypted bundles (ssh-manager-<stamp>.age)
└── .state/                         # transient: .lock, expiry/notify caches
```

`ssh-manager` resolves the home in this order:

1. `$SSH_MANAGER_HOME` (alias `$SSH_MANAGER_CONFIG_DIR`) if set - explicit override (tests / multiple configs)
2. otherwise the OS-standard dir above

A legacy `~/.sshmgr` home (from older versions) is **auto-migrated** to the
standard location on first run. `~/.ssh` itself is unchanged - it's the generated
output. `sshmgr doctor` prints the resolved home so it's always clear where state
lives.

### Configuration precedence (user first, then shipped default)

The **manifest** is always the source of truth and is read from your home
(`init` seeds an empty one). For the **provider catalog**, your
`<home>/providers.json` is used **if present**; otherwise the full default catalog
**shipped with the package** (kept byte-identical to the repo's `src/config/providers.json`)
is used - so providers work out of the box, and you only create your own file to
customize them.

## First run

```sh
sshmgr init                  # create/converge the home + starter manifest/inventory/.env
# edit <home>/manifest.json for your profiles/hosts (or: sshmgr import / profile add / host add)
sshmgr reconcile --dry-run   # preview what would change
sshmgr reconcile             # build ~/.ssh from the manifest (prompts about a passphrase on a TTY)
sshmgr config check          # confirm it's in sync (exit 0)
sshmgr knownhosts init --all # create per-profile known_hosts + pin reachable hosts
```

`sshmgr init` is safe to re-run: every run (re)creates the directory structure and
re-asserts perms, and seeds any missing files **without** touching your existing
manifest/`.env`. To reset the seed files to defaults, use `sshmgr init --force` (it overwrites
them in place). Add `--backup` to first copy the old ones into `<home>/.state/`.

Passphrases are **off by default** but a conscious choice: `reconcile`/`keygen`
prompt once on a terminal, or take `--passphrase`/`--no-passphrase` to script it.

## Permissions / groups

Perms are load-bearing (SSH refuses loose key/config modes) and secrets must
never be group/world readable. The tooling fixes this automatically:

```sh
sshmgr doctor --fix          # re-assert perms on managed ~/.ssh paths + secrets
make doctor FIX=1            # same, via the front door, against the binary you just built
```

`reconcile` sets the correct modes as it writes, and `doctor` reports and repairs
them afterwards - the two walk the same enumeration, so they cannot disagree
about what is managed.

We never `chgrp`/`chown` (that needs root); denying group and other access is the
safe, correct hardening for a single-user tool - run it as the file owner. On
Windows the equivalent is an owner-only ACL applied with `icacls`, since mode
bits do not apply there.

---

[← Docs index](../README.md#documentation)
