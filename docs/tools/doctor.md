# `doctor` — check, and repair, the managed tree

Twelve checks over the environment, the config home and `~/.ssh`, with an exit
code that is a verdict rather than a success flag.

```sh
sshmgr doctor           # report
sshmgr doctor --fix     # report, and repair what it can
sshmgr doctor --json    # the same report, for a script
sshmgr doctor --strict  # every dangling-key state is fatal (CI)
```

## What it checks

| Check | Reports |
|---|---|
| `os` / `runtime` | the platform, and that the binary needs no interpreter |
| `hard deps` | OpenSSH is present: `ssh`, `ssh-keygen`, `ssh-add`, `ssh-keyscan` |
| `optional` | which of `age`, `sops`, `gh`, `glab`, `age-plugin-yubikey` are missing |
| `home` / `ssh` | the resolved config home and `~/.ssh`, so an override is visible |
| `providers` | whether the catalog is the shipped default or a user file |
| `agent` | whether `ssh-agent` is running and how many keys it holds |
| `known_hosts` | whether the trust store exists, and which hosts are unpinned |
| `config drift` | whether the rendered block still matches the manifest |
| `perms` | every managed path whose mode is not what it should be |
| dangling keys | declared-but-missing, half a pair, on disk but untracked, unwired |
| duplicate keys | the same key material under two profiles |
| stale predecessors | archived keys older than `SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS` |

## Exit codes

**0 when the tree is clean, 1 when it is not.** That is a verdict, not an error —
`doctor` succeeded either way. Everything else in the tool uses 1 for failure, so
a script that only wants to know "did it run" should check for output rather than
the code.

Without `--strict`, a key that is declared but has never been minted is a warning
and does not fail the run: it is an ordinary state on a machine that has not
reconciled yet. With `--strict` every dangling state is fatal, which is what makes
it usable as a CI gate.

## `--fix`

Repairs permissions, and only permissions. It re-asserts the canonical mode on
every managed path in `~/.ssh` and on the config-home secrets — the same
enumeration the check walks, so the two cannot disagree about what is managed.

It does not mint keys, render config or pin hosts. Those are `reconcile` and
`knownhosts pin`, and they are separate because they change more than metadata.

## `--json`

The scripting surface. Empty collections serialize as `[]` and `{}`, never
`null`, so a consumer never has to distinguish "none" from "absent":

```sh
sshmgr doctor --json | jq -e '.perm_issues | length == 0'
```

Keys: `ok`, `home`, `ssh_dir`, `preflight_ok`, `providers_source`, `agent`,
`known_hosts`, `config_in_sync`, `perm_issues`, `orphan_keys`, `duplicate_keys`,
`unpinned_hosts`, `alias_collisions`, `old_keys`, `stale_old_keys`,
`dangling_keys`, `stranded_legacy_home`.

Diagnostics go to stderr, so the document on stdout is always parseable.

---

[← Docs index](../../README.md#documentation)
