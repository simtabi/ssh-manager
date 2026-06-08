## What & why

<!-- What does this change and why? Link the issue it closes. -->

Closes #

## Invariant checklist

- [ ] Manifest stays the source of truth; no hand-edited `~/.ssh/config`.
- [ ] Config changes go through the single renderer (`core/renderer.py`).
- [ ] State I/O is atomic and under the advisory lock; no secrets added to git.
- [ ] Perms (700/600/644) preserved; converging commands stay idempotent.

## Checks

- [ ] `make lint` (ruff + `mypy --strict`) is green.
- [ ] `make test` is green; added/updated tests where relevant.
- [ ] `CHANGELOG.md` / `README.md` updated as needed.
