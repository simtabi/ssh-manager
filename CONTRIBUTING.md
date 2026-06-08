# Contributing to ssh-manager

Thanks for your interest! `ssh-manager` is a Simtabi LLC open-source project.

## Ground rules (the invariants)

A small set of invariants must never be weakened for convenience:

1. **The manifest is the source of truth**; `~/.ssh` is generated output.
2. **The tool owns the SSH config** - never hand-edit rendered files; change the
   manifest (or `host`/`profile` verbs) and re-render. Unmodeled options go
   through a host `raw_options` passthrough.
3. **One renderer** drives `config render`, `config check`, and `reconcile`.
4. **Secrets never touch git**; **atomic writes** under an **advisory lock** for
   all state; **perms are load-bearing** (700/600/644).

If an invariant seems to block you, raise it in an issue rather than routing
around it.

## Dev setup

```sh
.build/bootstrap.sh       # venv + editable install + pre-commit hooks
# ssh-manager's home is the OS config dir (~/.config/ssh-manager); set SSH_MANAGER_HOME=$PWD/.devhome to sandbox a throwaway home in dev
. .venv/bin/activate
make doctor              # verify environment
```

## Before you push

```sh
make lint                # ruff + mypy --strict
make test                # pytest
make e2e                 # end-to-end smoke
make feature-check       # per-command checklist (every feature)
```

- **Type-hinted throughout**; `mypy --strict` must pass on `src/`.
- **No business logic in `cli.py`/`tui.py`** - they only parse args and call the
  Facade. All subprocess calls go through `util/proc.py`; all state I/O through
  `util/jsonstore.py` + `util/lock.py`.
- **Idempotency tests** for every converging command (run twice → no diff, no
  clobbered keys). **Security tests** for perms and secret exclusion.
- Pre-commit (`gitleaks` + `detect-private-key`) must pass - never commit a secret.

## Commits & PRs

- Set `git config user.email "19682005+imanimanyara@users.noreply.github.com"`.
- Subject ≤ 72 chars, imperative mood; body explains *why*. No emoji.
- Keep PRs small, green, and scoped to one concern. Update `CHANGELOG.md` and
  `README.md` as verbs land.
