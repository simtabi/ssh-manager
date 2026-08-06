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
git clone https://github.com/simtabi/ssh-manager && cd ssh-manager
make build               # -> bin/sshmgr
make doctor              # verify the environment, using the binary you just built
```

There is no bootstrap step: Go 1.26 is the only prerequisite. ssh-manager's home
is the OS config dir (`~/.config/ssh-manager`); set
`SSH_MANAGER_HOME=$PWD/.devhome` to sandbox a throwaway one while developing.

## Before you push

```sh
make check               # the CI gate plus lint: gofmt, build, vet, tests, golangci-lint
make lint-all            # lint every GOOS - one run only ever sees one
make e2e                 # end-to-end smoke against a real binary (build-tagged)
make feature-check       # the per-command assertions
```

`make ci` is the gate CI itself runs, and `check` is a strict superset of it, so
the two cannot drift. Run `lint-all` when touching `internal/platform` or any
build-tagged file: a single golangci-lint run analyses one GOOS and reports
everything the others reference as dead code.

## Invariants

These are enforced by tests, not by convention. Breaking one turns a test red.

- **Identity is `profile/key`, never a bare key name.** Two profiles may declare
  the same file name — one person under two organisations does exactly that — so
  anything keyed on the name alone will act on the wrong key.
- **A command that edits the manifest re-renders the config; one that only
  touches key files does not.** Leaving the render to a later `reconcile` means a
  successful edit ends with the tool reporting drift it just created.
- **An inventory record survives while any `KeyRef` owns it.** Deriving the
  surviving set from hosts alone drops the record of a declared key that has
  merely become unwired, and expiry then cannot see it.
- **`keysvc` reports, `keyaudit` interprets.** A new dangling state belongs in
  `keyaudit`; a new fact about a key belongs in `keysvc`.
- **No business logic in `internal/cli`** — verbs parse flags and call a service.
  `internal/cli` is a leaf: nothing under `internal/` may import it.
- **State I/O goes through `internal/util/fs` under `internal/util/lock`**, and
  every external command is an argv slice, never a shell string. The tool's whole
  external-binary surface is pinned by a test.

## Where things live

- `internal/services/lifecycle` owns all three guarded deletions (profile, host,
  key); `internal/services/editor` owns the manifest edits underneath them.
- `internal/services/keyaudit` owns every dangling-key state and the text that
  explains it.
- `config/manifest.json` is the shipped example *and* the renderer's golden
  fixture *and* the fixture the e2e test copies in. Changing its shape means
  updating the renderer goldens in the same commit.
- **Idempotency tests** for every converging command (run twice → no diff, no
  clobbered keys). **Security tests** for perms and secret exclusion.
- Pre-commit (`gitleaks` + `detect-private-key`) must pass - never commit a secret.

## Commits & PRs

- Set `git config user.email "19682005+imanimanyara@users.noreply.github.com"`.
- Subject ≤ 72 chars, imperative mood; body explains *why*. No emoji.
- Keep PRs small, green, and scoped to one concern. Update `CHANGELOG.md` and
  `README.md` as verbs land.
