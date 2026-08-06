## What & why

<!-- What does this change and why? Link the issue it closes. -->

Closes #

## Invariant checklist

- [ ] Manifest stays the source of truth; no hand-edited `~/.ssh/config`.
- [ ] Config changes go through the single renderer (`src/internal/core/renderer`).
- [ ] State I/O is atomic and under the advisory lock; no secrets added to git.
- [ ] Perms (700/600/644) preserved; converging commands stay idempotent.

## Checks

- [ ] `make check` (gofmt, build, vet, tests, golangci-lint) is green — plus `make lint-all` if this touches `src/internal/platform` or a build-tagged file.
- [ ] `make test` is green; added/updated tests where relevant.
- [ ] `CHANGELOG.md` / `README.md` updated as needed.
