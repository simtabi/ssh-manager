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
make build               # -> build/sshmgr (empties build/ first, every time)
make doctor              # verify the environment, using the binary you just built
```

There is no bootstrap step: Go 1.26 is the only prerequisite. ssh-manager's home
is the OS config dir (`~/.config/ssh-manager`); set
`SSH_MANAGER_HOME=$PWD/.devhome` to sandbox a throwaway one while developing.

## Before you push

```sh
make check               # the CI gate plus lint: gofmt, build, vet, tests, golangci-lint
make ci-linux            # the same gate inside a linux container (needs docker)
make lint-all            # lint every GOOS - one run only ever sees one
make e2e                 # end-to-end smoke against a real binary (build-tagged)
make feature-check       # the per-command assertions
```

`make ci` is the gate CI itself runs, and `check` is a strict superset of it, so
the two cannot drift. `make ci-linux` runs that gate on Linux, on the Go version
`go.mod` asks for — `check` only ever tests the machine you are on, and
`lint-all` cross-compiles for other systems without running anything on them, so
a Linux-only failure is otherwise invisible until CI reports it. That matters
when CI cannot: a runner outage, a fork without Actions, or no network. Run `lint-all` when touching `internal/platform` or any
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

## Two roots

The Go module is `src/`, not the repository root. `go.mod` is there, so every
`go` command has to run there — the Makefile does this for you with `go -C src`,
and `make` is the supported way to build. Running `go test ./...` from the
repository root finds no packages and passes without testing anything.

Everything the repository *presents* stays at the top: `README.md`, `LICENSE`,
`CHANGELOG.md`, `docs/`, `.github/`, `Makefile`, and `build/`.

| Where | What |
|---|---|
| `src/` | `go.mod`, `cmd/`, `internal/`, `config/`, `scripts/`, `.goreleaser.yaml`, `.golangci.yml` |
| repo root | the README and friends, `docs/`, `.github/`, `Makefile`, `build/` |

Import paths carry both segments: `github.com/simtabi/ssh-manager/src/v3/internal/cli`.
The `v3` is Go's required major-version suffix, not a directory. Package names in
this document are written relative to the module, so `internal/cli` means
`src/internal/cli` on disk.

Two things deliberately cross the boundary, and both say so where they occur:
GoReleaser runs from the repository root with `builds[].dir: src`, because its
archive globbing cannot climb out of its working directory to reach `LICENSE`;
and `scripts/build-all.sh` runs in the module — `go build` needs that — while
writing into the root `build/`.

## Build output

Everything generated goes to `build/` at the repository root — one directory,
not one per module — and nothing goes anywhere else:

| Path | What | Tracked |
|---|---|---|
| `build/targets.txt` | the release target matrix | yes |
| `build/sshmgr` | `make build` output | no |
| `build/dist/` | GoReleaser and `src/scripts/build-all.sh` artifacts | no |

`make clean` empties it, keeping `targets.txt`. There was a `bin/` alongside it
until this layout was settled — two directories for one idea — and `make clean`
removed a top-level `dist/` that GoReleaser had stopped writing to, so it left
every release artifact in place while reporting success. A `build/` appearing
anywhere else (`src/build/`, say, from a tool run in the wrong directory) is a
mistake, and `.gitignore` refuses to track one.

## Where things live

- `internal/services/lifecycle` owns all three guarded deletions (profile, host,
  key); `internal/services/editor` owns the manifest edits underneath them.
- Releases carry two tags on one commit: `vX.Y.Z` drives the release, and
  `src/vX.Y.Z` is how Go resolves a module that lives in a subdirectory. The
  workflow creates the second one; see [docs/release.md](docs/release.md).
- `internal/services/keyaudit` owns every dangling-key state and the text that
  explains it.
- `src/config/manifest.json` is the shipped example *and* the renderer's golden
  fixture *and* the fixture the e2e test copies in. Changing its shape means
  updating the renderer goldens in the same commit.
- **Idempotency tests** for every converging command (run twice → no diff, no
  clobbered keys). **Security tests** for perms and secret exclusion.
- `gitleaks` runs in CI over the full history — never commit a secret. A finding
  on a published commit cannot be fixed by editing the working tree; retire it by
  fingerprint in `.gitleaksignore`, with a note saying what the string is and why
  it is not a secret.

## Why some tests cite `python-final`

This was a Python program until v3. No Python remains in the tree, but a number
of tests cite `python-final:src/ssh_manager/...` — a tag, so `git show` resolves
every one of them.

Those citations are evidence, not nostalgia. `TestTheCommandSurfaceMatchesThePythonItReplaced`
compares the whole cobra tree against the verb and flag list it replaced, in both
directions, which is what makes "no command was lost in the rewrite" a checked
claim rather than a recollection; the parity tests name the file each case was
derived from so a reader can confirm the behaviour was ported rather than
invented. Deleting the citations would leave the assertions without a source.

A bare `foo.py` reference is different — it points at a path that exists nowhere
and should be removed or rewritten. If a comment names Python, it should either
cite the tag or explain a decision (why a type has a method ceiling, why the JSON
has the shape it does).

## Commits & PRs

- Set `git config user.email "imanimanyara@users.noreply.github.com"` — the
  address every commit in this repo has been authored under.
- Subject ≤ 72 chars, imperative mood; body explains *why*. No emoji.
- Keep PRs small, green, and scoped to one concern. Update `CHANGELOG.md` and
  `README.md` as verbs land.
