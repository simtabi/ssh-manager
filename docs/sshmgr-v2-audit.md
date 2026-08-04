# sshmgr v2 — status audit (2026-08-04, updated after Phase 4)

Comprehensive handoff document for continuing this work in another tool (Claude
Code CLI). Supersedes `docs/ssh-worklist.md` for anything about the v2
refactor — that file is the older, narrower personal-machine notes this
project grew out of and is now mostly stale/completed.

**Source plan**: `/Users/imanimanyara/.cursor/plans/sshmgr_v2_layout_refactor_8e1d97ac.plan.md`
(full technical detail for every phase below lives there; this document is the
authoritative status tracker since that plan's own frontmatter checklist is
stale — many items it marks `pending` are actually done, per the commit log
and the verification in this document).

**Repo**: `/Users/imanimanyara/Artisan/projects/opensource/simtabi/sshmgr`
**Branch**: `sshmgr-v2`, branched from `main` at `f0acce8` ("Adopt Simtabi Go
release standard via GoReleaser")
**Working tree**: clean as of this audit. `go build ./...`, `go vet ./...`,
`gofmt -l .`, and `go test ./...` all pass.

## Overview / intent

Close secret-leak findings (passphrase in argv, plaintext key archives,
world-readable host inventory), refactor `sshmgr` so the generated `~/.ssh`
matches a flat layout (single inline config, single known_hosts, profile dirs
holding only keys), add profile/key lifecycle management with dangling-key
detection and cleanup commands, fix a catalogue of bugs, finish de-Pythonizing
the repo, and ship a signed installable binary with a TUI at CLI parity.

Target layout (the contract):

```
~/.ssh/
├── config          # 0600 - ALL Host blocks inline, grouped by profile banner
├── known_hosts     # 0600 - single trust store, hashed, sshmgr entries tagged
└── profiles/
    └── <org>/      # 0700 - keys ONLY
        ├── <user>_<service>-ed25519       # 0600
        └── <user>_<service>-ed25519.pub   # 0644
```

No `profiles/*/config`. No `profiles/*/known_hosts`. Profile = org, key file =
person.

---

## DONE

### Phase 1 — Secret handling in argv/terminal/keygen

Commits: `8bedfcf`, `18db560`, `5187afc`

- **Passphrase never touches argv.** `ssh-keygen -N <passphrase>` is gone;
  the passphrase is written to `ssh-keygen`'s stdin pipe instead
  (`internal/services/keystore/keystore.go`). Regression test asserts no
  passphrase appears in argv.
- **No-echo terminal prompt with confirmation**, backed by a new
  `internal/platform` package (`ioctl_darwin.go`, `ioctl_linux.go`,
  `term_unix.go`, `term_windows.go`, `term_other.go`, `platform.go`) — termios
  toggling on Unix, `SetConsoleMode` on Windows, falls back to a plain read
  when stdin isn't a TTY. Used by `reconcile`, `keygen`, `rotate`.
- **Key generation is symlink-safe and atomic.** `Generate` mints into a fresh
  `os.MkdirTemp` inside the profile dir (0700) then renames the pair into
  place; `exists` uses `Lstat` instead of `Stat` so a planted symlink is
  detected, not followed and written through.
- **`IdentitiesOnly yes` is hardcoded per host block**, adjacent to the
  `IdentityFile` it constrains, rather than relying on `global_options`
  (which is still honoured as an explicit override).
- Profile-scoped key-name uniqueness (relaxed from global) landed as the
  clean baseline this branch started from.

### Phase 2 — Artifact privacy

Commits: `c032cef`, `53dc04a`, `3dbda16`, `6896fe6`, `5bfa485`

- **Routine snapshots no longer contain private keys.** `snapshots.go` now
  allowlists `config`, `known_hosts`, `*.pub`, `authorized_keys` for plaintext
  archives; `HoldsKeyMaterial` detects legacy tarballs that predate this.
  `Restore` overlays instead of `RemoveAll`-ing, so it never deletes a private
  key it has no copy of.
- **Key-destroying operations require an encrypted backup first.**
  `rotate` and `keygen --force` write an `age`-encrypted bundle
  (`backupKeysBeforeDestroying` in `internal/cli/bundle.go`) before discarding
  a predecessor, refusing to proceed with no `age` recipient configured unless
  `--no-key-backup` is passed.
- **Bundle/restore stream through `age`** via `io.Pipe` instead of staging a
  plaintext tarball in `$TMPDIR` (`internal/services/bundler/bundler.go`).
  Path-traversal checks added on restore (`layDown`/`within`). Regression
  tests (`bundler_security_test.go`, `age_live_test.go`) assert no plaintext
  residue in `$TMPDIR` and correct behavior with the real `age` binary.
- **Artifact permission/retention sweep**: `providers --export` → 0600;
  `.staging`/`.mint-*` now covered by perms repair; `profiles/*/old/`
  predecessors get age-based staleness reporting via `doctor`
  (`SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS`, default 90 days); audit log rotates by
  size; `dist/*.age` bundles prune on write (`--keep`); `SSH_MANAGER_SNAPSHOT_RETAIN`
  is honoured; `migratesvc` re-tightens permissions after moving a legacy
  home; config-home secrets (`manifest.json`, `inventory.json`,
  `providers.json`, caches, audit-log sidecars) are all enumerated in
  `homeperms.SecretPerms` and enforced by both `doctor` and `reconciler`.
- **`known_hosts` privacy**: dropped to 0600 (from 0644) and added to the
  managed-perms enumeration; hostnames are hashed on write using stdlib
  `crypto/hmac`+`crypto/sha1` (never `ssh-keygen -H`, which leaves a plaintext
  `.old` file behind); `HashKnownHosts yes` is pinned in the rendered
  `Host *` block so ssh's own TOFU-accepted entries are hashed too.
  Interoperability verified against real `ssh-keygen -F`.

### Phase 3 — Layout refactor

Commits: `cb0c4fd`, `f3154f5`

- **`RenderRootConfig` emits every profile's `Host` blocks inline** under a
  `# --- profile: <name> ---` banner, in manifest (file) order, with
  `Host *` always last (load-bearing: OpenSSH takes the first value it sees
  per keyword). `RenderProfileConfig` and `Include profiles/*/config` are
  gone; `RenderAll` now returns exactly one file (`config`). Golden-style
  ordering test in `renderer_test.go`.
- **`known_hosts` collapsed to one store.** `Manifest.KnownHostsFile()` lost
  its profile argument; the three remaining hardcoded per-profile joins
  (`doctor.go`, `deployer.go`, `rotator.go`) fixed. The `knownhosts` service
  API collapsed to match: `PathFor(profile)` → `Path()`, `Ensure`/`Add`/`Init`
  lost the storage-selector argument. `knownhosts init`'s `PROFILE`/`--all`
  now select which hosts to *scan*, not which file to write (`--user` flag
  removed — there's no separate store left).
- **Tagging + reference-counted pruning.** Every line sshmgr writes carries a
  trailing `sshmgr` comment tag (sshd(8)'s free-text comment field). New
  `Service.Prune(m)` removes a tagged line only once no manifest host (in any
  profile) still resolves to its `host:port`; `Service.Adopt(m)` opt-in-tags
  matching untagged (user-owned) lines. Untagged lines are never touched by
  `Prune`. (Prune/Adopt are implemented and tested; **not yet wired into any
  CLI command** — that's part of Phase 4's `clean`/`profile delete --purge`.)
- **One-shot migration.** `config render` now calls
  `knownhosts.MigrateLegacyStores()` (merges any leftover
  `profiles/*/known_hosts` into the single store, hashing/tagging as it goes,
  then deletes the legacy files), snapshotting first; no-op on a tree with
  none. `profiles/*/config` prunes automatically via the pre-existing orphan
  loop in `configsvc.configFilesOnDisk` now that `RenderAll` never produces
  those paths.
- **Duplicate `Host` alias is now a hard `manifest.Load` validation error**
  (`checkAliasCollisions` in `manifest.go`), same-profile or cross-profile —
  promoted from a doctor-only warning, since inline rendering makes a
  collision deterministically dead config rather than filesystem-order
  dependent.

### Phase 4 — Profile, key, and host lifecycle

Commits: `85f9c57`, `bb1151f`, `311d99a`, `f8d60b4`, `f54c6a3`, `2167589`

- **Keys are first-class.** `Profile` gained an optional `keys` list
  (`manifest.KeySpec`: `name`, optional `type`, optional `rotate_after_days`;
  overrides are stored unset rather than defaulted-on-load so re-saving never
  freezes today's defaults into every key). Per-profile name uniqueness,
  `safeSegment` names, and a type allowlist (`key.IsKnownAlgo`) are enforced by
  `manifest.validate`. Backwards compatible both ways: a host naming a key
  absent from the list still implicitly declares it, and `keys` serializes only
  when non-empty, so a pre-`keys` manifest is byte-stable across load/save.
  `EditProfile` now mutates the loaded profile instead of rebuilding it (it
  would have dropped the list).
- **`KeyRefs()` returns the union** of declared and host-derived keys, grouped
  by profile in manifest order (host-derived first, then declared-only). New
  resolvers `KeySpecFor` / `KeyTypeFor` / `RotateAfterDaysFor`.
- **The reconciler mints declared keys.** `planMint` walks `KeyRefs` instead of
  `IterResolved` and carries `plannedKey{Ref, Hosts}` (an unwired key has no
  host); per-key type and rotation reach `ssh-keygen` and the inventory record;
  `ensureTree` creates a directory for every profile that owns a key, not only
  those with hosts. `validate` switched to `KeyRefs` for the same reason. New
  `Reconciler.MintRef` mints exactly one key and refuses to overwrite an
  existing file.
- **New `internal/services/keysvc`** — the key-first read layer (`query` stays
  host-first). `Row`/`Detail` join manifest + inventory + disk; stats with
  `Lstat` and never reads private material. It names four dangling states
  (`unwired`, `missing`, `half-pair`, `unrecorded`) using **the vocabulary
  Phase 5's `keyaudit` should adopt**, so that phase subsumes this rather than
  renaming it.
- **New commands**: `key add` (declares + mints; `--host` wires an existing
  host, refused in a `shared` profile; otherwise prints the UNWIRED warning and
  the finishing command), `key list` (fingerprint, expiry, hosts, deployment
  status, dangling notes), `key delete` (refuses while a host resolves to the
  key), `profile delete --purge`, `show`, `clean`.
- **`show <profile|alias|profile/key>`** reports all four places the truth
  lives: manifest, key files (paths + modes + fingerprints, **never contents** —
  asserted by a test against a real generated key), the Host block rendered from
  the manifest (`renderer.RenderHostBlockFor`), and the matching known_hosts
  lines decoded out of the hashed store (`knownhosts.EntriesFor`). Reads the
  `.pub` fingerprint from disk as well as the recorded one and flags a
  MISMATCH.
- **Delete is one transaction** — new `internal/services/lifecycle`: manifest +
  inventory (via `editor`), config re-render, reference-counted
  `knownhosts.Prune`, then key files **only under `--purge`** (with the
  encrypted backup first, on rotate/keygen's terms). A purge takes rotation
  predecessors in `old/` too, and stops at any file sshmgr did not create —
  reporting the directory rather than deleting it. `DeleteProfile` now prunes
  inventory records for *every* key a profile owns, not only those its hosts
  resolve to (a declared hostless key's record used to survive).
- **`clean [--dry-run] [--adopt]`** finally wires up `Prune`/`Adopt`, plus the
  temp-residue sweep. `Prune`, `Adopt` and the two candidate previews now share
  one classifier (`Service.scan`), so `--dry-run` cannot drift from the run that
  follows; `FindTempArtifacts` was split out of `CleanTempArtifacts` for the
  same reason. A stale *hashed* line is reported by key type + fingerprint,
  never a host name — recovering that name is what hashing prevents.

### Phase 4 follow-ups — the three loose ends, closed

Commits: `9ede8d3`, `bdb8a00`, `74dfb07`, `baa5a50`, `bf32782`

Three things were flagged at the end of Phase 4; chasing each one turned up
something beyond it.

- **The hosts-vs-keys bug class is now closed, not just its first instance.**
  The profile-delete fix (`f8d60b4`) had a sibling: `editor.pruneIdents` decided
  which inventory records survive by walking hosts, so a key that was *declared*
  and used by exactly one host lost its record when that host was deleted -
  leaving the key declared and on disk with nothing tracking its expiry. Both now
  derive from `KeyRefs`. A failure to compute the surviving set is returned
  rather than swallowed (it means we cannot prove a record is unused, which is no
  licence to delete it), and pruned names are sorted so a deletion reports the
  same list every run.
  The rest of the class was audited and is correct as-is: `rotator` and
  `deployer` refuse an unwired key outright ("no host in the manifest uses key
  X"), `agent` loads only host-derived keys by intent, `doctor.orphanKeys`
  already uses `KeyRefs`, and `renderer`/`configsvc`/`knownhosts`/`netstat`/
  `query` are host-centric by nature.
- **`host delete` is folded into `lifecycle`** — re-renders, prunes pins, and no
  longer touches directories (the profile survives it, unlike profile delete).
  What becomes of the key is classified rather than assumed: still used by
  another host (nothing to report), still declared (UNWIRED - reported with both
  ways out, and `--purge` deliberately leaves the files, since the profile still
  owns the key), or gone from the manifest entirely (the orphan case, and the
  only one `--purge` deletes). That covers Phase 5's "host delete warns when it
  strands a key" ahead of time.
- **The render inconsistency is resolved by an invariant**: *a command that
  changes the manifest renders the config; a command that only touches key files
  does not*. It follows from the config being a pure function of the manifest -
  any manifest edit makes the file stale, and staleness is exactly what `diff`
  and `doctor` report, so the old behaviour ended each edit by creating the
  problem the next command complained about. `key add --host` was the concrete
  bug: it wired a host to a new key and left the config pointing at the old one.
  `keygen`/`rotate` change no manifest state and still render nothing. The
  add/edit verbs now take the mutation guard they had been skipping (part of
  Phase 6's "editor mutations bypass the mutation guard"), and
  `editor.DeleteResult` lost its `Format`, whose text had become false in both
  halves.
- **Found while testing the above: the mutation guard deadlocked on its own
  lock.** `lock.Acquire` blocks until free and flock is per file descriptor, so
  the second call in one process waited forever on a lock that process already
  held - silently, since the guard prints nothing. One CLI command mutates once
  and exits, which hid it; **the TUI is one process that mutates repeatedly, so
  the second action of any session froze** (`tui.go` reconcile / knownhosts /
  rotate). The lock is now taken once per process and reused.
- `--purge` now names the files it declines to delete instead of only saying the
  directory still holds some.

All of the above is fully tested (`go test ./...` green) and committed on
`sshmgr-v2`. No dry-run/simulation — every change compiles, vets, and passes
its test suite.

---

## REMAINING (in plan order)

Full technical detail for each item is in the plan file linked above; summary
below is enough to resume without re-reading it, but the plan has exact line
numbers, code snippets, and reasoning for trickier ones.

### Phase 5 — No dangling keys (not started)

- New package `internal/services/keyaudit` computing seven dangling states
  from manifest + inventory + disk (`Lstat` only, never reads key contents):
  **untracked**, **unwired**, **missing**, **half-pair**, **unrecorded**,
  **stale-inventory**, **loose**. Shared by `doctor`, `key list`, `show`,
  `clean`, and the notifier.
  **Start from `internal/services/keysvc` (Phase 4), don't duplicate it**: it
  already computes four of the seven (`unwired`, `missing`, `half-pair`,
  `unrecorded`) under those exact names, with the `Lstat`-only/never-read-key-
  material rule, and `key list`/`show` consume them. The three it does not have
  (**untracked**, **stale-inventory**, **loose**) all need a directory walk
  rather than a manifest-driven lookup, which is the real reason to promote it
  to `keyaudit` — either extend `keysvc` in place or have `keyaudit` wrap it.
- `doctor` gains a dangling-keys section; **untracked/unwired/half-pair**
  fail `OK()`, the rest warn; `--strict` escalates everything (for CI).
  Currently `doctor.OK()` ignores orphans entirely, and orphan detection
  skips any private key lacking a `.pub` sibling — both are live bugs to fix
  as part of this, not new behavior.
- Inline surfacing: `reconcile` and `key add` warn on creation, `key list`/
  `show` mark each key, `host delete` warns when it strands a key. Notifier
  needs to take manifest + ssh dir so the daily notification covers dangling
  counts.

### Phase 6 — Remaining bugs (not started; verified still present as of this audit)

- **Critical** — rotator commit (`rotator.go` ~L229-241) is a four-step
  `os.Rename` sequence with no rollback; partial failure can leave the
  canonical identity path empty while the live key sits in `old/` or
  `.staging/`. Real lockout risk. *(Confirmed still present.)*
- **High**:
  - `keygen --force` overwrite map is keyed by bare basename
    (`internal/cli/keygen.go` `overwrite := map[string]bool{}`, and
    `reconciler.go` `Mint(... overwrite map[string]bool)`), so confirming
    overwrite of `imani_github-ed25519` regenerates it in **both**
    `personal` and `adelsaiq`. Needs keying by `manifest.KeyRef`.
    *(Confirmed still present — this is the one live-data-destroying bug for
    this machine's actual naming scheme.)*
  - `inventory.Save`/`manifest.Save` still use plain `os.WriteFile`
    (confirmed: `internal/core/inventory/inventory.go:127`,
    `internal/core/manifest/manifest.go:925` — line moved in Phase 4), despite
    package comments claiming atomicity, and `WriteFile` on an existing file
    keeps its current mode. Route through `fs.WriteTextAtomic`. Now more
    pressing: `lifecycle` writes the manifest and inventory back-to-back inside
    one delete.
  - `deploy` bypasses the mutation guard entirely — confirmed no
    `snapshotBeforeMutation`/`lock.Acquire` call anywhere in
    `internal/cli/deploy.go`. *(The editor half of this is closed: every
    profile/host/key add·edit·delete verb takes the guard as of `baa5a50`.
    `deploy` is what is left.)*
  - `doctor.OK()` ignoring orphans / the `.pub`-pair hole — folded into
    Phase 5.
- **Medium** — rollback reports `Committed = true` when targets were
  unreachable (rotator.go ~L332-360); TUI swallows `inv.Save` errors
  (tui.go:333,364); `netstat` bare-name filter spans profiles (netstat.go:32)
  and `keygen` rejects `profile/key` (now `reconciler.planMatches`,
  reconciler.go:286 — accepts a profile name or host alias, not the composite
  form; `keysvc.matches` and `validate.selectorMatches` both already accept it,
  so this is the odd one out); expiry table shows basename only
  (cli/expiry.go:46-56); `query.byPath` is last-wins on duplicate paths
  (query.go:91-94 — `keysvc.record` shows the fix: sort the fingerprints so the
  tie breaks deterministically instead of by map order); rotator skips archival
  when the fingerprint read fails (rotator.go:164-166); `knownhosts.go` proceeds
  when lock acquisition fails.
- **Low** — `profile/key` display sweeps in `diff.go`, `notifier.go`,
  `recover.go`, deploy/rotate headers; stale comments at `doctor.go:35` and
  `manifest.go` (line drifted after Phase 3 edits — re-check);
  `editor.basename` splits on `/` only. *(`KeyRefs` claiming a sort it does not
  do was fixed in Phase 4 when the doc comment was rewritten.)*

### Phase 7 — Portability and de-Python (not started)

- Delete the Python tree — confirmed `src/ssh_manager` still present. Tag
  first. Two Go tests read Python data files (`recover_test.go:15`,
  `initsvc_test.go:13`) — repoint at `//go:embed` copies.
- Rewrite `Makefile` for Go (confirmed: no `install:` target exists yet;
  targets still dispatch to `.venv/bin/sshmgr`). Invert CI so `go test` is
  the primary gate; drop Python/Windows-Python jobs.
- `internal/platform` already exists (built in Phase 1 for the no-echo
  read) — still need to absorb the other 15+ scattered
  `runtime.GOOS == "darwin"` sites and `emitUseKeychain` threading into it.
- Demote `ssh-copy-id` on Windows (hard preflight dep, not shipped with
  Windows OpenSSH).
- Fix `importer.expanduser` missing `~\` handling, and
  `expiry.keyName`/`editor.basename` splitting on `/` only.
- Purge stale `internal/engine/embed/engine` references from `.gitignore`
  and `docs/release.md`.

### Phase 8 — Distribution (not started)

- `.goreleaser.yaml` confirmed has **no `signs:` block** — checksums are
  unauthenticated. Add cosign keyless signing over `checksums.txt`.
- `make install` (confirmed: doesn't exist yet) — default `~/.local/bin`,
  `PREFIX=/usr/local` for global, **must refuse a group-/world-writable
  target dir** (macOS `/usr/local/bin` is admin-group-writable by default,
  and the notifier's launchd job runs the installed binary daily — a
  group-writable install dir is a persistent code-exec foothold).
- `go install github.com/simtabi/ssh-manager/cmd/sshmgr@latest` support.
- `sshmgr completion bash|zsh|fish|powershell` (cobra provides nearly free).
- Config stays strictly per-user via `$SSH_MANAGER_HOME` — deliberately no
  `/etc` support.

### Phase 9 — TUI parity (not started)

TUI confirmed still a 9-action stdin menu (browse, show config, expiry,
audit, reconcile, knownhosts pin, deploy, rotate, snapshots, quit). Missing:
`doctor`, `validate`, `keygen`, `key add/list/delete`, `show`, `clean`, `init`,
`import`, `bundle`/`restore`, `rollback`, `net`, `providers`, `load`,
profile/host CRUD. (`cli.writeKeyTable` is already factored for reuse the way
`writeExpiryTable` is, and `keysvc`/`lifecycle` are UI-free, so the key verbs
should be cheap to surface.) Note the TUI's *existing* actions only started
working past the first mutation with `74dfb07` — before that the second
mutating action in a session froze on the advisory lock, so anything this
phase adds should be exercised twice in one session, not once.
No TTY detection. `docs/tools/tui.md` still describes a rich/questionary UI
that no longer exists (Python-era doc). Plan recommends bubbletea, done last
so it builds on a stable service layer from the earlier phases.

### Phase 10 — Tests and docs (not started)

- Rewrite catalogued layout assertions in `.build/e2e.sh` and
  `.build/feature-check.sh` (the Go-side test files this refers to —
  `renderer_test.go`, `configsvc_test.go`, `tui_test.go`, `knownhosts_test.go`
  — were already rewritten as part of Phase 3's own verification, but the
  shell-script-level e2e/feature-check fixtures have not been touched and
  likely still assert the old per-profile layout).
- Security regressions already largely exist per-phase (passphrase-in-argv,
  snapshot-no-keys, bundle-no-tmpdir-residue, known_hosts 0600+hashed,
  IdentitiesOnly-always-present, symlink-refused, providers.json 0600) — this
  phase is really about the *cross-cutting* fixtures: dup-basename coverage
  against `keygen --force`/deploy/rotate/rollback (blocked on Phase 6's
  `KeyRef`-keying fix) and migration-from-old-layout end-to-end. **Profile
  delete with/without `--purge` and pruning sparing foreign + still-live pins
  landed with Phase 4** (`internal/services/lifecycle/lifecycle_test.go`), as
  did `show`-never-prints-key-material (`internal/cli/show_test.go`) and
  dry-run-matches-the-real-run for prune/adopt
  (`internal/services/knownhosts/prune_test.go`). Command-level coverage started
  with `internal/cli/mutate_test.go`, which drives real verbs through
  `newRootCmd().Execute()` against a `t.Setenv`-ed `$HOME` + `$SSH_MANAGER_HOME`
  — copy that harness rather than inventing another. Most verbs still have no
  end-to-end test.
- **Docs are confirmed stale**: `SECURITY.md:37` and
  `docs/configuration.md:76` both still describe "per-profile
  `UserKnownHostsFile`" as the model, which Phase 3 removed. Also update
  `docs/architecture.md`, `docs/tools/knownhosts.md`, `CHANGELOG.md`. The
  honest replacement framing (from the plan): the only cross-profile hostname
  on this machine's actual manifest is `github.com`, where all three profiles
  want the same pin anyway, and hashing + 0600 buys more real protection than
  the old per-profile split did.
- **Phase 4 added user-facing surface with no docs yet**: the manifest `keys`
  list (`docs/configuration.md`) and the `key add/list/delete`, `show`,
  `clean`, `profile delete --purge`, `host delete --purge` verbs (`docs/tools/`,
  one page per subsystem per the org docs standard). Also document the render
  invariant — manifest edits render, key-file commands do not — since it
  replaces the "run `sshmgr reconcile` to apply" instruction that any existing
  doc or muscle memory still carries.

### Phase 11 — Apply to this machine (not started)

- `sshmgr config render`, diff against the current hand-maintained
  `~/.ssh/config` before accepting (that file has drifted from what any
  renderer version has emitted — see `docs/ssh-worklist.md` for the specific
  divergences recorded 2026-08-02).
- `sshmgr doctor` until the dangling report is empty (depends on Phase 5).
- Re-add the simtabi public key to its GitHub account (`github-simtabi`
  currently fails auth — key not deployed/removed from that account, not a
  tool bug).
- Pin `[sc.its.unc.edu]:443` once on the UNC VPN (the one genuinely unpinned
  host on this machine).
- Backfill `deployments` for the three working GitHub identities so `audit`
  stops reporting all seven keys as needs-redeploy.

---

## Gotchas for whoever resumes this

1. **The plan file's YAML frontmatter checklist is stale.** Trust this
   document's DONE/REMAINING split, not the `status: pending`/`completed`
   fields at the top of the plan file — several phases were completed after
   the frontmatter was last touched.
2. **Prune/Adopt are wired up as of Phase 4** (`sshmgr clean`, and
   `profile delete`). They now share one classifier, `Service.scan`, with the
   `PruneCandidates`/`AdoptCandidates` previews — add any new prune/adopt
   predicate there, not in a second copy, or `--dry-run` starts lying.
3. **`internal/platform` already exists** (Phase 1) — extend it in Phase 7
   rather than creating a second platform package. Same rule for
   `internal/services/keysvc` (Phase 4) and Phase 5's `keyaudit`.
   `internal/services/lifecycle` now owns all three deletions (profile, host,
   key); a fourth belongs there too.
4. **Two invariants worth not breaking**, both load-bearing as of the Phase 4
   follow-ups: *manifest edits render the config, key-file commands do not*
   (`cli.applyManifestEdit`), and *a record/file survives while anything in
   `KeyRefs` owns it* — never re-derive "in use" by walking hosts, since a
   declared key has none.
5. Every phase so far has been committed as its own commit(s) on
   `sshmgr-v2` with a real commit message (`git log sshmgr-v2` for the exact
   sequence) — keep that granularity; don't squash unrelated phases together.
6. Full verification loop after every change: `gofmt -l .`, `go build ./...`,
   `go vet ./...`, `go test ./...` — all must be clean before moving on.
7. This machine's real `config/manifest.json` (used by several renderer
   tests as a fixture, e.g. `renderer_test.go`) has 4 non-empty profiles
   (`work`, `personal`, `simtabi`, `development`) and one empty one
   (`school`) — tests assert against this exact shape, so don't change that
   fixture file without updating the tests that golden-check against it.
   `manifest_test.go` also asserts it still round-trips with no `keys` field,
   which is the guard that the Phase 4 schema addition stays invisible to
   manifests that don't use it.
8. **Phase 11 has not been run, and must not be run without asking.** Nothing
   in this branch has touched the real `~/.ssh` on this machine; every smoke
   test used a throwaway `$SSH_MANAGER_HOME` + `$HOME`.

---

## Continuation prompt for Claude Code CLI

The prompt text lives in `docs/sshmgr-v2-continue-prompt.txt` (kept separate
from this file so it's trivial to feed to a CLI via `$(cat ...)` without
quoting problems). Launch with:

```bash
cd /Users/imanimanyara/Artisan/projects/opensource/simtabi/sshmgr
claude "$(cat docs/sshmgr-v2-continue-prompt.txt)"
```
