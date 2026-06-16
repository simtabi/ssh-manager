# Installation

## Requirements

- **Python ≥ 3.11**
- OpenSSH: `ssh-keygen`, `ssh-add`, `ssh-copy-id`, `ssh-keyscan` (hard deps)
- Optional, degrade gracefully: `age`, `sops`, `gitleaks`, `gh`, `glab`,
  `age-plugin-yubikey`

## Install

```sh
pip install git+https://github.com/simtabi/ssh-manager.git   # or pipx
```

## From the repo (development)

```sh
git clone https://github.com/simtabi/ssh-manager && cd ssh-manager
.build/bootstrap.sh       # creates .venv, editable install, pre-commit hooks
. .venv/bin/activate
sshmgr doctor             # verify the environment
```

`.build/bootstrap.sh` sets up the venv, the editable install, and pre-commit
hooks. The `.env` (and the rest of the home) is created by `sshmgr init`, which
seeds it from the shipped `.env-example` template at mode `0600` (gitignored).

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
**shipped with the package** (kept byte-identical to the repo's `config/providers.json`)
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
make perms                   # scripts +x, config secrets 0600, dirs 0700, ~/.ssh fixed
sshmgr doctor --fix          # re-assert perms on managed ~/.ssh paths + secrets
make doctor FIX=1            # same, via the front door
```

`bootstrap.sh` runs the perms pass automatically at the end of install. We never
`chgrp`/`chown` (that needs root); denying group/other access is the safe,
correct hardening for a single-user tool - run it as the file owner.
