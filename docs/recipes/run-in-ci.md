# Run it in CI

Non-interactive, sandboxed, and failing loudly.

```yaml
- name: Check the SSH config is in sync
  env:
    SSH_MANAGER_HOME: ${{ github.workspace }}/.sshmgr
    SSH_MANAGER_AUTO_PIN: "0"      # no ssh-keyscan; the runner has no network trust
  run: |
    sshmgr init
    sshmgr reconcile --no-pin --yes
    sshmgr config check            # exit != 0 on drift
    sshmgr doctor --strict         # exit != 0 on any dangling key
```

The pieces that matter:

- **`SSH_MANAGER_HOME`** points the whole config home at the workspace, so
  nothing touches the runner's real `~/.config`.
- **`SSH_MANAGER_AUTO_PIN=0`** stops `reconcile` reaching for `ssh-keyscan`.
  Without it a runner with no route to your hosts spends its timeout on every one.
- **`--strict`** turns every dangling-key state fatal. Without it `doctor` warns
  about a key that is declared but never minted and still exits 0.
- **`--yes`** on anything that changes `~/.ssh`. A runner has no terminal, so the
  confirmation is skipped and the command proceeds either way — but passing it
  states the intent rather than depending on the environment, and it keeps the
  step correct if it is ever run by hand.

Exit codes are the whole contract: **0 for success, 1 for everything else.**
`doctor` and `validate` return 1 on an unclean report rather than on a crash, and
a declined confirmation exits 1 silently.

For machine-readable output:

```sh
sshmgr doctor --json | jq '.perm_issues, .unpinned_hosts'
```

Reference: [`doctor`](../tools/doctor.md) · [Configuration](../configuration.md).

---

[← Docs index](../../README.md#documentation)
