# sshmgr — Python → Go migration plan

Single source of truth for the v2 migration. Supersedes every earlier planning
document in this repo (see **Prior art**).

- **Inventory baseline commit:** `03d1f92beed00d9f335e4e69f4183fe0f71de16f`
- **Python source of truth:** tag **`python-final`** (`adea887`) — 88 `.py`
  files. *The Python tree is no longer in the working directory; see the
  protocol deviation below.*
- **Branch:** `go-v2`
- **Status vocabulary:** `TODO`, `IN_PROGRESS`, `PORTED_UNVERIFIED`, `VERIFIED`,
  `DROPPED`. Only `VERIFIED` and `DROPPED` close a row.

---

## Protocol deviation, recorded up front

**Phase 4 (Python removal) already happened, out of order and ungated.** The
tree was deleted in commit `fe8cef1` ("Delete the Python implementation") during
earlier work on branch `sshmgr-v2`, before any feature matrix existed and
therefore before any row was `VERIFIED`. This violates the rule that no Python
file is touched until Phase 4 and that Phase 4 is gated on a fully closed
matrix.

What this does **not** cost us: the tree was tagged `python-final` immediately
before deletion, so every file is readable (`git show python-final:<path>`) and
runnable (`git worktree add /tmp/py python-final`). Behaviour can still be
characterised against real Python. Every Python citation in this document is
therefore given as `python-final:<path>` and is verifiable.

What it does cost us: the drift check specified for Phase 4 cannot be run
forward from a baseline — it must instead be run *backward*, confirming that the
deletion commit removed exactly the files this matrix accounts for and nothing
else. That is now a Phase 4 task (see below), not a formality.

**Restoring the tree into `go-v2` purely to delete it again at the end is
rejected as theatre** — it would produce two no-op commits and change nothing
about what can be verified. Recorded in `OPEN_QUESTIONS.md` (Q1).

---

## Corrections to Phase 1

Recorded rather than quietly edited, because an inventory whose errors are
invisible is not evidence.

| # | Claim in the Phase 1 matrix | Reality | Fixed |
|---|---|---|---|
| 1 | K6 `internal/core/authkeys`: "No test files in package" | `authkeys_test.go` existed at the baseline commit, added in `af96ff7`. Mis-transcribed when building the matrix. | Row K6 now cites the pre-existing tests plus the ones added in Phase 3. The other 13 TODO rows were re-checked and are correct. |

---

## Prior art

Every migration-related artifact found in the repo, on branches, and in history.

| Artifact | What it is | Verdict |
|---|---|---|
| `docs/sshmgr-v2-audit.md` | 500-line status tracker for an 11-phase v2 effort (secret handling, layout refactor, lifecycle, dangling keys, bug catalogue, de-Python, distribution, TUI, tests/docs, apply-to-machine). Has per-phase narrative, commit hashes, and "REMAINING" sections. | **PARTIAL** — rich input material, but organised by *work phase*, not by *feature*. No feature-level inventory, no Python file-path evidence, no per-feature status. Below the sufficiency bar. Mine it; do not follow it. |
| `docs/sshmgr-v2-continue-prompt.txt` | Continuation prompt for driving the above audit from a CLI. | **STALE** — process scaffolding for a superseded workflow. |
| `docs/ssh-worklist.md` | Personal-machine notes the project grew out of (2026-08-02). The audit itself calls it "mostly stale/completed". | **STALE** — retain only for the Phase 11 machine-specific facts. |
| `/Users/imanimanyara/.cursor/plans/sshmgr_v2_layout_refactor_8e1d97ac.plan.md` | The upstream plan the audit tracks. **Outside the repo.** Its own frontmatter checklist is documented as wrong. | **CONFLICTING** — audit explicitly says not to trust its status fields. Out-of-repo, so not a repo artifact to fold in; treat as historical. |
| `docs/architecture.md`, `docs/features.md`, `docs/configuration.md`, `docs/installation.md` | Product docs. Describe the Python install path (`pip install`, venv, pytest) for an implementation that no longer exists. | **STALE / CONFLICTING** — contradict the code. Phase 5 rewrites them. |
| `CHANGELOG.md` | Release history; references the Python engine. | **PARTIAL** — historical Python references are legitimate and stay (Phase 4 justified-hits list). |
| `go.mod`, 151 `.go` files across 45 packages | A complete-looking Go implementation: `cmd/sshmgr`, `internal/cli`, `internal/core/*`, `internal/services/*`, `internal/util/*`, `internal/platform`. | **PARTIAL** — substantial and it builds, but **no row inherits status from it**. Every feature backed by this code enters the matrix at `PORTED_UNVERIFIED` and is audited in Phase 3. |
| `.github/workflows/ci.yml` | Go build/vet/test/gofmt on ubuntu+macOS+windows; `pre-commit`; `gitleaks`. Python jobs already removed. | **PARTIAL** — no linter step (`golangci-lint`), no coverage gate. Phase 2 extends it. |
| `.goreleaser.yaml`, `.github/workflows/release.yml` | Pure-Go cross-compiled release, `CGO_ENABLED=0`. | **SUFFICIENT** for building; **PARTIAL** for signing (no `signs:` block). |
| `Makefile` | Go targets (`build`, `test`, `vet`, `fmt-check`, `check`, `e2e`, …). | **PARTIAL** — no `install`, no lint gate wired to CI. |
| `.build/e2e.sh`, `.build/feature-check.sh` | Shell end-to-end + per-feature assertion scripts driving the binary. | **PARTIAL** — real parity assets, but their assertions still encode the pre-v2 `~/.ssh` layout. High-value input for Phase 3. |
| Branches `main`, `sshmgr-v2` | `sshmgr-v2` carries all migration work (40 commits ahead of `main`). | **PARTIAL** — history, not a plan. |
| `internal/cli/migrate.go`, `internal/services/migratesvc` | **Not** Python→Go migration. Migrates the user's *config home* from legacy locations to XDG. | Named-collision only; recorded so nobody mistakes it for prior art. |

**Sufficiency verdict: nothing found meets the bar.** No artifact contains a
feature-level inventory with Python file-path evidence and per-feature status.
The matrix below is built from scratch against `python-final`.

**Conflicts noted.** Where documents disagree with code, code wins:
1. `docs/installation.md` + `README.md` describe `pip install`; no Python exists. → Code wins; docs are wrong (Phase 5).
2. `docs/tools/tui.md` describes a rich/questionary TUI; the Go TUI is a plain stdin menu. → Code wins; doc is wrong.
3. The audit claims phases 1–7 "fully tested"; that claim is package-level `go test` green, not feature parity vs Python. → Treated as unproven (`PORTED_UNVERIFIED`).

---

## Target architecture (Phase 2)

**Verdict on the existing Go layout: KEPT, with three changes.** It already
matches the org standard — thin `cmd/sshmgr` entrypoint, cobra tree confined to
`internal/cli`, small single-concern packages under `internal/core`,
`internal/services`, `internal/util`, build-tagged platform files. Replacing it
would discard 151 files of working code to arrive somewhere very close to where
it already is. What it lacked was gates, not structure.

### Module and layout

```
cmd/sshmgr/main.go        thin entrypoint; askpass short-circuit, then cli.Execute
internal/cli/             the cobra tree — the only package importing cobra
internal/core/            domain types, no I/O policy: manifest, inventory,
                          renderer, expiry, key, authkeys, providers
internal/services/        one concern each; composed by the CLI, never by
                          each other's internals
internal/platform/        every OS predicate; build-tagged terminal handling
internal/util/            leaf helpers: paths, perms, fs, lock, log, netcheck,
                          secrets, desktop, scheduler, httpjson, askpass
```

Module path `github.com/simtabi/ssh-manager` is unchanged — it is the import
path already published and referenced by `go install`.

### Changes made in Phase 2

| # | Change | Why |
|---|---|---|
| A1 | `.golangci.yml`: standard linters, **no path exclusions**, caps off | The default `max-same-issues: 3` reported 51 issues when there were **121**. A cap hides findings the same way an exclusion does. |
| A2 | Lint runs **per GOOS** (`make lint-all`, CI matrix) | golangci-lint analyses one GOOS per run: platform files behind `//go:build` are invisible, and `unused` reports anything only they reference as dead code. |
| A3 | `timerUnit` moved into `scheduler_linux.go` | A constant referenced only from a build-tagged file belongs in that file. |
| A4 | Exit codes decided only in `Execute` (`internal/cli/exit.go`) | 14 inline `os.Exit(1)` calls made every command untestable through `Execute`, which is the parity gate this migration depends on. |
| A5 | `make check` = fmt + vet + lint + test | One command reproduces the CI gate. |

### Error handling

Go `error` values throughout; no panics for control flow. Errors wrap with `%w`
and are compared with `errors.Is`. Two sentinels in `internal/cli/exit.go` cover
failures that are not faults — `errAborted` (declined confirmation) and
`errNotClean` (the report *is* the bad news: doctor, validate, config check,
deploy, rotate, net). Both exit 1 silently, since the message already reached the
user. Everything else prints `sshmgr: <err>` and exits 1.

**Exit-code contract (parity, cited):** 0 on success, 1 on everything else.
`python-final:src/ssh_manager/cli.py:59-62` (`_fail`), `:147` (doctor's
`0 if report.ok else 1`), `:343-344` et al (declined confirmations). No other
code was ever produced by the Python, and none is invented.

### Config, logging, concurrency

- **Config**: `internal/util/paths` resolves the home from `$SSH_MANAGER_HOME` /
  `$SSH_MANAGER_CONFIG_DIR`, else XDG. The manifest is the single source of
  truth; the rendered ssh config is a pure function of it.
- **Logging**: no logging framework. `internal/util/log` appends structured
  audit records for mutating operations; user-facing output is `fmt` to the
  command's own writer, which is what makes commands testable.
- **Concurrency**: deliberately almost none. The tool shells out to `ssh*`
  binaries and writes one user's dotfiles; the only concurrency is
  `bundler`/`snapshots` streaming through an `io.Pipe` with a goroutine per
  producer, and `exec.CommandContext` timeouts on every external call.
  Cross-process safety is an advisory `flock` (`internal/util/lock`), taken once
  per process by the mutation guard.

### Open architectural item

`internal/cli/tui.go` holds the TUI. The org standard puts Bubble Tea models in
a top-level `tui/` package so `internal/cli` stays importable. Not moved:
matrix row E4 is a rewrite (the current TUI is a plain stdin menu, deviation
D3), and moving it twice is waste. **Decision: move it when it is rewritten,
not before.**

---

## Feature matrix

Status legend: `PU` = PORTED_UNVERIFIED, `VERIFIED`, `D` = DROPPED, `T` = TODO.

**Counts as of the latest Phase 3 batch: VERIFIED 20 · PORTED_UNVERIFIED 70 ·
TODO 0 · DROPPED 0.** The core domain (K1–K6) is fully closed. Every row that had no test at any level is now closed;
what remains is auditing the 76 rows whose Go code predates this run. A row reaches VERIFIED only when its tests were written
or audited in this run and `go build`, `go vet`, `go test` and `golangci-lint`
were all green with it — the gate is `make check`.

"Go tests present" in Evidence means test files exist and passed `go test ./...`
at baseline; it is *not* parity evidence and does not confer `VERIFIED`.

### Entry points

| # | Feature | Python source | Behavior notes | Go target | Status | Evidence |
|---|---|---|---|---|---|---|
| E1 | `sshmgr` console entry point | `python-final:pyproject.toml` `[project.scripts]`; `python-final:src/ssh_manager/__main__.py` | Installed script → `ssh_manager.cli:main` | `cmd/sshmgr` | PU | `cmd/sshmgr/main.go` |
| E2 | Root CLI app + `--version` callback + banner | `cli.py:27-54,101-105` | Typer app; subapps `config`,`profile`,`host`,`notify`,`snapshots`,`knownhosts` | `internal/cli/root.go` | PU | `internal/cli/root_test.go` |
| E3 | Error→exit-code mapping | `cli.py:59-62,147,343-344`; `util/errors.py` | 0 on success, 1 on everything else. Declined confirmation → 1; doctor → `0 if ok else 1` | `internal/cli/exit.go` | PU | `exit_test.go::TestErrorClassification`, `::TestConfirmOrAbort`, `::TestNoCommandCallsOsExit`. Classification proven; **the code itself still needs a subprocess assertion in Phase 3** |
| E4 | TUI | `tui.py` (209 lines) | questionary/rich menu | `internal/cli/tui.go` | PU | `internal/cli/tui_test.go`; **known deviation** — plain stdin menu, not questionary |

### Commands (parity = same flags, same exit codes, same output contract)

| # | Command | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| C1 | `version` | `cli.py:101-105` | `internal/cli/root.go` | PU | `root_test.go::TestVersionCommand` |
| C2 | `tui` | `cli.py:107-117` | `internal/cli/tui.go` | PU | `tui_test.go` |
| C3 | `recover` | `cli.py:119-129` | `internal/cli/recover.go` | PU | `internal/services/recover/recover_test.go` |
| C4 | `doctor [--fix] [--json] [--strict]` | `cli.py:130-149` | `internal/cli/doctor.go` | PU | `internal/services/doctor/doctor_test.go`; `--strict` is a **new flag** (deviation D7) |
| C5 | `init [--force] [--backup]` | `cli.py:150-168` | `internal/cli/init.go` | PU | `internal/services/initsvc/initsvc_test.go` |
| C6 | `migrate` (config home) | `cli.py:169-184` | `internal/cli/migrate.go` | PU | `internal/services/migratesvc/*_test.go` |
| C7 | `import` | `cli.py:185-199` | `internal/cli/import.go` | PU | `internal/services/importer/importer_test.go` |
| C8 | `reconcile [--dry-run] [--no-pin] [--passphrase]` | `cli.py:200-220` | `internal/cli/reconcile.go` | PU | `internal/services/reconciler/reconciler_test.go` |
| C9 | `diff` | `cli.py:221-229` | `internal/cli/diff.go` | **VERIFIED** | `mutate_test.go::TestDiffReportsDriftWithoutTouchingAnything`, `::TestDiffCountsAKeyOnceNotOncePerHost` |
| C10 | `keygen [--force] [--yes] [--passphrase] [--no-pin]` | `cli.py:230-274` | `internal/cli/keygen.go` | PU | `reconciler_test.go::TestOverwriteIsScopedToOneProfile`; `cli/mutate_test.go::TestKeygenAcceptsAKeySelector` |
| C11 | `deploy <key> [target]` | `cli.py:275-293` | `internal/cli/deploy.go` | **VERIFIED** | `mutate_test.go::TestDeployRefusesAnUnmintedKey`, `::TestVerbsRejectUnknownSelectors`; service layer at row S4 |
| C12 | `list [--profile] [--provider] [--type] [--tag]` | `cli.py:294-309` | `internal/cli/list.go` | PU | `internal/services/query/query_test.go` |
| C13 | `view <selector>` | `cli.py:310-322` | `internal/cli/view.go` | PU | `query_test.go` |
| C14 | `load <profile>` | `cli.py:323-332` | `internal/cli/load.go` | PU | `internal/services/agent/agent_test.go` |
| C15 | `rotate <key> [--allow-unverified] [--yes]` | `cli.py:333-353` | `internal/cli/rotate.go` | PU | `internal/services/rotator/rotator_test.go` |
| C16 | `rollback <key> [--yes]` | `cli.py:354-365` | `internal/cli/rotate.go` | PU | `rotator_test.go::TestRotateThenRollback` |
| C17 | `expiry` | `cli.py:366-375` | `internal/cli/expiry.go` | PU | `internal/core/expiry/expiry_test.go` |
| C18 | `providers [--export]` | `cli.py:376-400` | `internal/cli/providers.go` | PU | `internal/core/providers/providers_test.go` |
| C19 | `net [selector]` | `cli.py:401-413` | `internal/cli/net.go` | **VERIFIED** | `mutate_test.go::TestNetReportsEveryHost`, `::TestNetFailsOnlyWhenAGatedHostIsDown`; service layer at row S21 |
| C20 | `validate [selector]` | `cli.py:414-428` | `internal/cli/validate.go` | PU | `internal/services/validate/validate_test.go` |
| C21 | `audit [--notify]` | `cli.py:429-437` | `internal/cli/audit.go` | PU | `internal/services/notifier/notifier_test.go` |
| C22 | `bundle` | `cli.py:438-453` | `internal/cli/bundle.go` | PU | `internal/services/bundler/bundler_test.go` |
| C23 | `restore <bundle>` | `cli.py:454+` | `internal/cli/bundle.go` | PU | `bundler_test.go` |
| C24 | `config check\|render\|show` | `cli.py` `@config_app` | `internal/cli/config.go` | PU | `internal/services/configsvc/configsvc_test.go` |
| C25 | `profile add\|edit\|delete` | `cli.py` `@profile_app` | `internal/cli/profile.go` | PU | `internal/services/editor/editor_test.go`, `lifecycle_test.go` |
| C26 | `host add\|edit\|delete` | `cli.py` `@host_app` | `internal/cli/host.go` | PU | `editor_test.go`, `lifecycle_test.go` |
| C27 | `notify install\|test` | `cli.py` `@notify_app` | `internal/cli/notify.go` | PU | `internal/util/scheduler/scheduler_test.go` |
| C28 | `snapshots list\|restore\|prune` | `cli.py` `@snapshots_app` | `internal/cli/snapshots.go` | PU | `internal/services/snapshots/snapshots_test.go` |
| C29 | `knownhosts init\|pin` | `cli.py` `@knownhosts_app` | `internal/cli/knownhosts.go` | PU | `internal/services/knownhosts/*_test.go` |
| C30 | `key add\|list\|delete` | **none** — no Python equivalent | `internal/cli/key.go` | PU | `keysvc_test.go`, `cli/key_test.go`. **Go-only addition** (deviation D1) |
| C31 | `show <selector>` | **none** | `internal/cli/show.go` | PU | `cli/show_test.go`. **Go-only addition** (D1) |
| C32 | `clean [--dry-run] [--adopt]` | **none** | `internal/cli/clean.go` | PU | `knownhosts/prune_test.go`, `cli/mutate_test.go`. **Go-only addition** (D1) |

### Core domain

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| K1 | Manifest model, validation, key resolution | `core/manifest.py` (307) | `internal/core/manifest` | **VERIFIED** | `manifest_test.go`: 11 pre-existing (audited) + `TestControlCharactersAreRejectedEverywhere`, `TestHostnameAndUserRejectFlagsAndWhitespace`, `TestProfileNamesAreSafePathSegments`, `TestDangerousOptionsRejectedInGlobalOptionsToo`, `TestOptionValuesAreStringifiedLikePydantic`, `TestSharedKeyNameLoadsAndStaysProfileScoped` |
| K2 | Inventory model + persistence | `core/inventory.py` (94) | `internal/core/inventory` | **VERIFIED** | `inventory_test.go`: 7 pre-existing (audited) + `TestSaveLoadRoundTripIsStable`, `TestRecordReplacesAnExistingFingerprint`, `TestNeedsRedeployTurnsOnVerifiedOnly`, `TestComputeExpiryArithmetic`, `TestCorruptInventoryIsAnErrorNotAFreshStart` |
| K3 | SSH config renderer | `core/renderer.py` (132) | `internal/core/renderer` | **VERIFIED** | `renderer_test.go` + `renderer_security_test.go` (9 pre-existing, audited); added `TestRenderHostBlockForMatchesTheRootConfig`, `TestRawOptionsKeepTheirDeclaredOrder`. **Verified against the v2 contract, not Python output** — see D4 and Q3 |
| K4 | Expiry engine | `core/expiry.py` (92) | `internal/core/expiry` | **VERIFIED** | `expiry_test.go`: pre-existing `TestComputeStates` (audited); added `TestClassificationBoundaries`, `TestWarnWindowIsTheLargestThreshold`, `TestCadenceIsWeeklyUntilSomethingIsDue`, `TestBannerNamesKeysUnambiguously`, `TestStatesSortMostUrgentFirst`, `TestRef` |
| K5 | Key-name grammar | `core/key.py` (53) | `internal/core/key` | **VERIFIED** | `key_test.go`: pre-existing `TestNormalizeSegment`, `TestBuildKeyName`, `TestSplitKeyName`, `TestAlgoOf` (audited); added `TestDeriveKeyNameFromRealAliases`, `TestNameRoundTrips`, `TestHardwareKeyTypesAreNotTruncated`, `TestIsKnownAlgo`, `TestNormalizeCollapsesAnythingUnsafeForAFilename` |
| K6 | authorized_keys parsing | `core/authorized_keys.py` (120) | `internal/core/authkeys` | **VERIFIED** | `authkeys_test.go`: `TestValidityAndBody`, `TestSameKeyAndCount`, `TestAddRemove` (pre-existing, audited); `TestLengthPrefixPastTheBlobIsRejected`, `TestTypeTokenMustMatchTheEncodedWireType`, `TestAddRemoveNormaliseFileEdges`, `TestCRLFInputIsNormalised` (added). **Bug fixed**: 32-bit integer overflow in the wire-blob bounds check — see Deviations D10 |

### Services

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| S1 | **Facade** (1356 lines — God object) | `services/facade.py` | *dissolved* — see Redesign R1 | PU | Split across `internal/services/*` + `internal/cli` |
| S2 | Reconciler | `services/reconciler.py` (200) | `internal/services/reconciler` | PU | `reconciler_test.go` |
| S3 | Rotator + rollback | `services/rotator.py` (322) | `internal/services/rotator` | PU | `rotator_test.go` |
| S4 | Deployer | `services/deployer.py` (141); tests `tests/test_deploy.py` | `internal/services/deployer` | **VERIFIED** | `deployer_test.go`: `TestDeployRecordsEveryHostUsingTheKey`, `TestDeployTwiceLeavesOneEntryPerTarget`, `TestManualDeployStillNeedsRedeploy`, `TestTargetAliasNarrowsToOneHost`, `TestUnreachableServerIsRecordedAsAnError`, `TestDeployRejectsUnknownAndUnmintedKeys`, `TestReportFormatNamesTargetsAndOutcome` |
| S5 | Bundler (age encrypt/restore) | `services/bundler.py` (221) | `internal/services/bundler` | PU | `bundler_test.go`, `bundler_security_test.go`, `age_live_test.go` |
| S6 | knownhosts | `services/knownhosts.py` (89) | `internal/services/knownhosts` | PU | `knownhosts_test.go`, `hash_test.go`, `prune_test.go` |
| S7 | Notifier | `services/notifier.py` (98) | `internal/services/notifier` | PU | `notifier_test.go` |
| S8 | Query (list/view) | `services/query.py` (166) | `internal/services/query` | PU | `query_test.go` |
| S9 | Editor (profile/host CRUD) | `services/editor.py` (202) | `internal/services/editor` | PU | `editor_test.go` |
| S10 | Importer | `services/importer.py` (270) | `internal/services/importer` | PU | `importer_test.go` |
| S11 | Keystore (ssh-keygen wrapper) | `services/keystore.py` (91) | `internal/services/keystore` | PU | `keystore_test.go` |
| S12 | Agent (ssh-add) | `services/agent.py` (26) | `internal/services/agent` | PU | `agent_test.go` |
| S13 | Config service | `services/configsvc.py` (164) | `internal/services/configsvc` | PU | `configsvc_test.go` |
| S14 | Preflight | `services/preflight.py` (60) | `internal/services/preflight` | **VERIFIED** | `preflight_test.go`: `TestCheckReportsEveryMissingDependency`, `TestOptionalDepsDoNotBlock`, `TestOneMissingHardDepBlocks`, `TestSSHCopyIDIsOptionalOnWindowsOnly`, `TestFormatNamesWhatIsWrong`, `TestOSNameCarriesTokenAndHumanName`. Deviation: `python_ok` → `RuntimeOK` constant true (D11) |
| S15 | Doctor | `facade.py` (doctor + helpers) | `internal/services/doctor` | PU | `doctor_test.go` |
| S16 | Snapshots | `util/fs.py` + `facade.py` | `internal/services/snapshots` | PU | `snapshots_test.go` |
| S17 | Validate | `facade.py::validate_keys` | `internal/services/validate` | PU | `validate_test.go` |
| S18 | Recover (fixkeys.sh) | `facade.py` + `data/fixkeys.sh` | `internal/services/recover` | PU | `recover_test.go` |
| S19 | Init service | `facade.py::init` | `internal/services/initsvc` | PU | `initsvc_test.go` |
| S20 | Config-home migration | `facade.py::migrate` | `internal/services/migratesvc` | PU | `migratesvc_test.go`, `perms_test.go` |
| S21 | netstat | `util/net.py` + `facade.py:1066-1078` | `internal/services/netstat` | **VERIFIED** | `netstat_test.go`: `TestStatusProbesEveryHostAndReportsItsProfile`, `TestSelectorFilters`, `TestBareKeyNameMatchesEveryProfileThatHasIt`, `TestVPNMetadataIsCarriedThrough`, `TestUnresolvableManifestIsAnError` |
| S22 | keyaudit (dangling keys) | **none** | `internal/services/keyaudit` | PU | `keyaudit_test.go`. **Go-only** (D1) |
| S23 | keysvc (key-first read layer) | **none** | `internal/services/keysvc` | PU | `keysvc_test.go`. **Go-only** (D1) |
| S24 | lifecycle (guarded deletion) | **none** (Python delete = manifest only) | `internal/services/lifecycle` | PU | `lifecycle_test.go`. **Go-only** (D1) |

### Providers (external integrations)

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| P1 | Provider protocol + base | `providers/base.py` (135) | `internal/core/providers/adapter.go` | PU | `adapter_test.go` |
| P2 | Registry + catalog | `providers/registry.py` (157) | `internal/core/providers/providers.go` + `default_providers.json` | PU | `providers_test.go` |
| P3 | GitHub (`gh`) | `providers/github.py` (125) | `internal/core/providers/vcs.go` | **VERIFIED** | `vcs_test.go`: `TestGitHubDeployAddsAndIsIdempotent` (2 subtests), `TestRemoveMatchesBodyNeverTitle`, `TestGitHubEnterpriseUsesTheEnterpriseToken` (2 subtests), `TestVCSFallsBackToManual` (2 subtests), `TestListFailureIsNotAnEmptyAccount`, `TestManageURLFollowsTheHost` |
| P4 | GitLab (`glab`) | `providers/gitlab.py` (109) | `internal/core/providers/vcs.go` | **VERIFIED** | `vcs_test.go::TestGitLabMirrorsGitHub` (2 subtests), plus the shared helpers covered by `TestRemoveMatchesBodyNeverTitle` and `TestManageURLFollowsTheHost` |
| P5 | Cloud REST VPS (DigitalOcean, Vultr, Hetzner, Linode, Scaleway, generic) | `providers/cloud.py` (436); tests `tests/test_cloud_providers.py` | `internal/core/providers/cloud.go` | **VERIFIED** | `cloud_test.go`: `TestDeployAddsAKeyThatIsNotThere`, `TestDeployIsIdempotent`, `TestDeployRenamesOurStaleTitleButNeverAUserLabel` (2 subtests), `TestVerifyAndRemoveMatchOnBodyNotLabel`, `TestNoTokenFallsBackToManual`, `TestAPIFailuresSurface`, `TestPerProviderResponseShapes` (4 subtests), `TestNumericIDsDoNotBecomeScientificNotation`, `TestDigitalOceanOverHTTP`, `TestPaginationIsBounded`. **Coverage limit below.** |
| P6 | Generic SSH (`ssh-copy-id`) | `providers/ssh_generic.py` (120) | `internal/core/providers/ssh_generic.go` | PU | Plain-`ssh` fallback is a **Go-only addition** (D6) |

### Platform layer

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| L1 | Platform protocol | `platforms/base.py` (50) | `internal/platform` | **VERIFIED** | `platform_test.go`: `TestReadLineStopsAtTheNewlineAndLeavesTheRest`, `TestReadLinePreservesContentButStripsCR`, `TestReadLineOnClosedInput`, `TestOSPredicatesAgreeWithGOOS`, `TestEmitUseKeychainOnlyOnMacOS`, `TestOSNameCarriesBothForms`, `TestReadSecretRefusesWithoutATerminal` |
| L2 | macOS (keychain, launchd, notify) | `platforms/macos.py` (73) | `internal/platform`, `internal/util/scheduler`, `internal/util/desktop` | PU | `scheduler_test.go`, `platform_test.go`; `desktop` still untested |
| L3 | Linux (systemd timer, notify-send) | `platforms/linux.py` (107) | same | PU | `scheduler_test.go`; Python had `tests/test_linux.py` |
| L4 | Windows (icacls, schtasks, toast) | `platforms/windows.py` (92); tests `tests/test_windows.py` | `internal/util/perms/{windows_acl,perms_windows}.go`, `scheduler/{windows_task,scheduler_windows}.go` | **PORTED_UNVERIFIED** | Argv/ownership logic extracted and covered on every platform: `windows_acl_test.go` (5 tests), `windows_task_test.go` (3 tests). **The exec wiring itself is not verified by this run** — it compiles only on Windows and only CI's Windows leg can execute it. See coverage limits and Q9. |

### Utilities

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| U1 | Paths / XDG resolution | `util/paths.py` (143) | `internal/util/paths` | PU | `paths_test.go` |
| U2 | Permissions | `util/perms.py` (55) | `internal/util/perms` | PU | `perms_test.go` |
| U3 | Filesystem (atomic write, snapshots) | `util/fs.py` (155) | `internal/util/fs` | **VERIFIED** | `fs_test.go`: `TestWriteTextAtomicWritesContentAndMode`, `…DoesNotTranslateNewlines`, `…ReplacesAndLeavesNoResidue`, `…ReassertsModeOnAnExistingFile`, `…CreatesTheParent`, `TestTempFileNameIsSweepable`, `TestEnsureDirForcesModeOnANewAndAnExistingDir`, `TestExists` |
| U4 | Advisory lock | `util/lock.py` (58) | `internal/util/lock` | PU | `lock_test.go` |
| U5 | Audit log | `util/log.py` (47) | `internal/util/log` | PU | `log_test.go` |
| U6 | Network probe | `util/net.py` (124) | `internal/util/netcheck` | PU | `netcheck_test.go` |
| U7 | Secrets (.env loading) | `util/secrets.py` (50) | `internal/util/secrets` | PU | `secrets_test.go` |
| U8 | Subprocess helper | `util/proc.py` (77) | *dissolved* into `os/exec` at call sites | PU | Redesign R2 |
| U9 | HTTP+JSON client | `util/http.py` (123) | `internal/util/httpjson` | **VERIFIED** | `httpjson_test.go`: `TestRequestJSONSendsHeadersAndParsesTheBody`, `TestEmptyResponsesBecomeAnEmptyMap`, `TestRetriesIdempotentRequests`, `TestDoesNotRetryNonIdempotentRequests`, `TestClientErrorsFailImmediatelyAndReportTheBody`, `TestErrorBodyIsTruncated`, `TestRetryAfterIsHonouredAndCapped`, `TestNonJSONResponseIsAnError`, `TestRedirectPolicyRefusesDowngradeAndStripsCredentials` (4 subtests) |
| U10 | JSON store | `util/jsonstore.py` (32) | *dissolved* into `manifest`/`inventory` Save/Load | PU | Redesign R3 |
| U11 | Error taxonomy | `util/errors.py` (27) | Go `error` values | PU | Redesign R4 |
| U12 | Presentation layer (rich) | `render.py` (208) | *dissolved* into per-command `Format()`/`write*Table` | PU | Redesign R5 |
| U13 | Config-home perms enumeration | `facade.py` | `internal/util/homeperms` | PU | `homeperms_test.go` |
| U14 | askpass helper | **none** — replaces `services/keystore.py:47-56` (`-N <passphrase>` in argv) | `internal/util/askpass` | **VERIFIED** | `askpass_test.go`: `TestServingGatesOnTheExactMarker`, `TestServeWritesTheSecretAndOneNewline`, `TestEnvironCarriesTheHandshake`, `TestEnvironDropsInheritedValuesRatherThanShadowingThem`, `TestSecretTravelsOnlyInTheEnvironment`. Security deviation — see D9 |

### Cross-cutting

| # | Feature | Python source | Go target | Status | Evidence |
|---|---|---|---|---|---|
| X1 | Env vars: `SSH_MANAGER_HOME`, `_CONFIG_DIR`, `_AGE_RECIPIENT`, `_AGE_IDENTITY_FILE`, `_AUTO_PIN`, `_SNAPSHOT_RETAIN` | `util/paths.py`, `services/bundler.py`, `services/knownhosts.py` | `internal/util/paths`, `internal/cli` | PU | `paths_test.go`, `retention_test.go`. Go adds `SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS` (D5) |
| X2 | Manifest/inventory JSON serialization (pydantic `model_dump`) | `core/manifest.py`, `core/inventory.py` | hand-written `MarshalJSON` | **VERIFIED** | `manifest_test.go::TestSerializationEmitsAllFieldsInFileOrder`, `::TestKeysOmittedWhenEmpty`, `::TestOptionValuesAreStringifiedLikePydantic`; `inventory_test.go::TestRecordSerializationMatchesPydantic`, `::TestSaveLoadRoundTripIsStable`. **Qualified**: parity is asserted on field order, null/`[]`/`{}` conventions and value stringification, and on save being byte-stable across a round trip — not by diffing against output from a running Python, which is no longer part of the build |
| X3 | Packaging | `pyproject.toml` (hatchling) | `.goreleaser.yaml` | PU | Python had `tests/test_packaging.py` |
| X4 | CI | `.github/workflows/ci.yml` | same, Go-only | PU | Lint gate added in Phase 2 (`golangci-lint`, per-GOOS) |
| X5 | Python test suite (37 files) | `tests/*.py` | Go `*_test.go` (across packages) | **T** | Per-file mapping in Coverage check |

---

## Dependency map

| Python dependency | Purpose | Go equivalent | Decision |
|---|---|---|---|
| `typer` | CLI framework | `github.com/spf13/cobra` | Replaced (already in `go.mod`) |
| `rich` | Terminal rendering | `text/tabwriter` + plain `fmt` | **Dropped** — see D2 |
| `questionary` | Interactive prompts | hand-rolled stdin prompts (`internal/cli/tui.go`) | **Dropped** — see D3 |
| `pydantic` | Model validation + serialization | stdlib `encoding/json` + hand-written validators | Replaced; strict decoding via `DisallowUnknownFields` |
| `python-dotenv` | `.env` loading | `internal/util/secrets` (custom) | Custom implementation |
| `jinja2` | Templating | `strings.Builder` in `internal/core/renderer` | Replaced — the only template is the ssh config |
| `pytest` | Tests | stdlib `testing` | Replaced |
| `mypy` | Types | compiler | Dropped (obviated) |
| `ruff` | Lint | `gofmt` + `go vet` (+ `golangci-lint`, Phase 2) | Replaced |
| `pre-commit` | Hooks | kept — now runs gofmt/vet/gitleaks | Retained (only Python left in CI, justified) |
| `hatchling` | Build backend | `go build` / GoReleaser | Replaced |

Zero third-party Go runtime dependencies beyond cobra. External *binaries*
(`ssh-keygen`, `ssh-add`, `ssh-keyscan`, `ssh-copy-id`, `age`, `gh`, `glab`)
are unchanged and remain runtime requirements.

---

## Redesign list

Constructs that must not be transliterated.

| # | Python construct | Go approach | Status |
|---|---|---|---|
| R1 | `SshManagerService` facade, 1356 lines, every verb hanging off one object | Dissolved into per-concern services under `internal/services/*`; the CLI composes them. No God object. | PU |
| R2 | `util/proc.py` subprocess wrapper | `os/exec` directly at call sites, with `exec.CommandContext` timeouts | PU |
| R3 | `util/jsonstore.py` generic JSON store | Typed `Save`/`Load` on `manifest.Manifest` / `inventory.Inventory` | PU |
| R4 | Exception hierarchy (`util/errors.py`) used for control flow | Go `error` values; `fmt.Errorf` with `%w`; no panics for control flow | PU |
| R5 | `render.py` rich renderables | Each result type owns a `Format() string`; tables via `text/tabwriter` | PU |
| R6 | pydantic validators/`model_dump` | Hand-written `MarshalJSON`/`UnmarshalJSON` preserving field order and null/`[]`/`{}` conventions | PU |
| R7 | Platform classes with runtime dispatch (`platforms/*.py`) | Build-tagged files (`*_darwin.go`, `*_windows.go`, `*_other.go`) + `internal/platform` predicates | PU |
| R8 | Provider classes with inheritance | `providers.Provider` interface + small structs | PU |

---

## Deviations from Python (intentional, non-silent)

| # | Deviation | Justification |
|---|---|---|
| D1 | **New commands with no Python counterpart**: `key add/list/delete`, `show`, `clean`; new services `keyaudit`, `keysvc`, `lifecycle` | Added during v2 work to close dangling-key and lifecycle gaps. Out of scope for *parity*; in scope for *verification*. |
| D2 | No `rich` output (colour, boxes, trees) | Zero-dependency binary; `tabwriter` output is pipe-safe by default. Loses colour. |
| D3 | TUI is a plain stdin menu, not questionary | Recorded as a gap; Phase 9 of the prior effort. `docs/tools/tui.md` is wrong until then. |
| D4 | `~/.ssh` layout changed: single inline `config`, single `known_hosts`, `profiles/<org>/` holds keys only | Deliberate v2 contract change. **Breaks output parity with Python by design.** |
| D5 | New env var `SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS` | Archived-predecessor staleness reporting; no Python counterpart. |
| D6 | `GenericSSH` falls back to plain `ssh` when `ssh-copy-id` is absent | Windows OpenSSH does not ship `ssh-copy-id`. |
| D7 | `doctor --strict` | CI gate for dangling keys; no Python counterpart. |
| D8 | A `key_name` may repeat across profiles; identity is `profile/key` | **Corrected — the earlier wording had this backwards.** Python *rejected* a manifest where two profiles used one `key_name` (`manifest.py::_v_key_name_uniqueness`), because rotate/deploy resolved a bare name to hosts while assuming a single profile directory, so a shared name could mint in one profile and deploy to another's hosts. v2 lifts the ban because it removed the hazard: identity is `manifest.KeyRef`, and every lifecycle op resolves through it. A widening — manifests Python refused now load, and none that loaded before break. Pinned by `TestSharedKeyNameLoadsAndStaysProfileScoped`. |
| D9 | Passphrases reach `ssh-keygen` through the askpass protocol, not `-N` | The Python passed the passphrase in argv (`keystore.py:47-56`), which is world-readable via `ps` and `/proc/<pid>/cmdline` for the life of the process. `internal/util/askpass` re-executes sshmgr as its own helper and passes the secret in the environment. |
| D11 | preflight reports `RuntimeOK` as a constant true | The Python gated on CPython >= 3.11 (`preflight.py:MIN_PYTHON`). A compiled Go binary carries its runtime, so the check has no meaning; the actionable half - the hard/optional binary scan - is unchanged. |
| D10 | `authkeys` rejects a wire-blob length prefix above `MaxInt32` | Python's ints are arbitrary-precision, so the bounds check could not overflow. Go's `int` is 32 bits on the 386/armv6/armv7 builds sshmgr ships, where the original `4+int(n) > len(blob)` wrapped negative and panicked on a crafted `authorized_keys` line. Checked in `uint64` now. |

> **D4 is the most important entry here.** A large part of this migration is
> *not* a like-for-like port: the on-disk layout was intentionally redesigned.
> Parity gates for rendering/known_hosts rows must be written against the **v2
> contract**, not against Python's output, and the matrix rows for K3/S6/S13
> must say so when they are verified.

---

## Known coverage limits

Stated rather than left implicit, so a VERIFIED row is not read as more than it
is.

- **P5, per-provider request paths.** The shared orchestration is covered with a
  fake `restOps`; the field mapping for DigitalOcean, Vultr, Hetzner and Linode
  is covered from realistic payloads; and **DigitalOcean alone** is exercised
  over a real local HTTP server (URL, method, auth header, pagination). Vultr,
  Hetzner, Linode, Scaleway and the generic REST adapter share that code path,
  so what is unverified for them is their own URLs and verbs - e.g. Vultr's
  `PATCH` rename versus DigitalOcean's `PUT`. A typo there would pass every test
  in the suite.
- **No adapter has been run against a live API** by this migration, in Go or in
  Python. The tests pin the shapes the Python's own tests asserted plus the
  shapes the Go code expects; where those agree, both could still be wrong about
  the real API. Recorded in `OPEN_QUESTIONS.md` (Q8).
- **X2's byte-parity is asserted structurally, not by execution.** The tests pin
  field order, the null/`[]`/`{}` conventions, value stringification and
  save-stability. They do not diff against output from a running Python, which
  would need the interpreter and the deleted tree back in the build. A field
  pydantic emitted that no test names could still be missing.
- **The Windows exec wiring (L4) is unverified by this run.** `SetPerms` and
  `Install` compile only on Windows, so `icacls`/`schtasks` are never actually
  invoked outside CI's Windows leg. Everything decidable without Windows - the
  argv, its order, the principal list, owner resolution - is covered on all
  platforms. What is not: that `icacls` still takes those flags, and that the
  commands succeed against a real ACL. **This row cannot reach VERIFIED without
  either accepting CI as evidence or a Windows machine** (Q9).
- **VCS adapters are exercised through a stand-in `gh`/`glab` on PATH**, which
  covers argv, the environment overlay and the JSON parsing, but not the real
  CLIs' behaviour. A `gh` that changed its flag names would pass these tests.
- **Scaleway** has no shape test: its list response is built through the generic
  `objectOps` path with spec-driven field names rather than the fixed mapping
  the other four use.

## Coverage check — every `.py` file at `python-final`

51 source files + 37 test files = 88 total. Every one is accounted for.

### Source (`src/ssh_manager/**`, 51 files)

| File | Matrix row(s) |
|---|---|
| `__init__.py` | Non-feature — package marker + `__version__` (→ X3) |
| `__main__.py` | E1 |
| `cli.py` | E2, E3, C1–C29 |
| `tui.py` | E4, C2 |
| `render.py` | U12 / R5 |
| `core/__init__.py` | Non-feature — package marker |
| `core/manifest.py` | K1 |
| `core/inventory.py` | K2 |
| `core/renderer.py` | K3 |
| `core/expiry.py` | K4 |
| `core/key.py` | K5 |
| `core/authorized_keys.py` | K6 |
| `services/__init__.py` | Non-feature — package marker |
| `services/facade.py` | S1, S15–S20, U13, U14 |
| `services/reconciler.py` | S2 |
| `services/rotator.py` | S3 |
| `services/deployer.py` | S4 |
| `services/bundler.py` | S5 |
| `services/knownhosts.py` | S6 |
| `services/notifier.py` | S7 |
| `services/query.py` | S8 |
| `services/editor.py` | S9 |
| `services/importer.py` | S10 |
| `services/keystore.py` | S11 |
| `services/agent.py` | S12 |
| `services/configsvc.py` | S13 |
| `services/preflight.py` | S14 |
| `providers/__init__.py` | Non-feature — package marker |
| `providers/base.py` | P1 |
| `providers/registry.py` | P2 |
| `providers/github.py` | P3 |
| `providers/gitlab.py` | P4 |
| `providers/cloud.py` | P5 |
| `providers/ssh_generic.py` | P6 |
| `platforms/__init__.py` | Non-feature — package marker |
| `platforms/base.py` | L1 |
| `platforms/macos.py` | L2 |
| `platforms/linux.py` | L3 |
| `platforms/windows.py` | L4 |
| `util/__init__.py` | Non-feature — package marker |
| `util/paths.py` | U1, X1 |
| `util/perms.py` | U2 |
| `util/fs.py` | U3, S16 |
| `util/lock.py` | U4 |
| `util/log.py` | U5 |
| `util/net.py` | U6, S21 |
| `util/secrets.py` | U7 |
| `util/proc.py` | U8 / R2 |
| `util/http.py` | U9 |
| `util/jsonstore.py` | U10 / R3 |
| `util/errors.py` | U11 / R4 |

### Tests (`tests/**`, 37 files) — row X5

| File | Covers | Go counterpart status |
|---|---|---|
| `__init__.py`, `conftest.py` | Non-feature — fixtures | n/a |
| `test_manifest.py` | K1 | `manifest_test.go` |
| `test_renderer.py` | K3 | `renderer_test.go` |
| `test_expiry.py` | K4 | `expiry_test.go` |
| `test_reconcile.py` | S2 | `reconciler_test.go` |
| `test_rotate.py` | S3 | `rotator_test.go` |
| `test_deploy.py` | S4 | **missing** |
| `test_bundle.py`, `test_age_roundtrip.py` | S5 | `bundler_test.go`, `age_live_test.go` |
| `test_knownhosts.py` | S6 | `knownhosts_test.go` |
| `test_query.py` | S8 | `query_test.go` |
| `test_editor.py` | S9 | `editor_test.go` |
| `test_import.py` | S10 | `importer_test.go` |
| `test_keygen_audit.py`, `test_overwrite.py` | C10 | `reconciler_test.go` |
| `test_validate.py` | S17 | `validate_test.go` |
| `test_recover.py` | S18 | `recover_test.go` |
| `test_init_perms.py` | S19, U2 | `initsvc_test.go`, `perms_test.go` |
| `test_providers.py`, `test_provider_integration.py` | P1, P2 | `providers_test.go`, `adapter_test.go` |
| `test_cloud_providers.py` | P5 | **missing** |
| `test_ssh_generic.py` | P6 | **missing** |
| `test_paths.py` | U1 | `paths_test.go` |
| `test_net.py` | U6, S21 | `netcheck_test.go` (netstat **missing**) |
| `test_linux.py` | L3 | partial (`scheduler_test.go`) |
| `test_windows.py` | L4 | **missing** |
| `test_tui.py`, `test_tui_pty.py` | E4 | `tui_test.go` (no PTY test) |
| `test_cli_yes.py` | E2, confirmation flags | **missing** |
| `test_smoke.py` | E1–E3 | **missing** |
| `test_packaging.py` | X3 | **missing** |
| `test_security.py`, `test_safety.py`, `test_hardening.py`, `test_robustness.py`, `test_audit_fixes.py` | cross-cutting | partially covered by `bundler_security_test.go`, `keybackup_test.go`, `agehelp_test.go` |

**Test-coverage gaps are the main Phase 3 workload:** 9 Python test files have
no Go counterpart at all.

---

## Phase 4 preconditions (revised for the out-of-order deletion)

1. Every matrix row `VERIFIED` or `DROPPED`.
2. **Backward drift check**: `git diff python-final..HEAD -- '*.py'` must show
   only deletions, and the deleted set must equal the 88 files enumerated above.
   Any file deleted but *not* in this matrix is an unaccounted feature.
3. Removal verification: `find . -name "*.py"` empty (excluding `.venv/`, which
   is untracked local residue and must also be removed);
   `grep -ri python` returns only justified hits, each listed.
4. Clean-clone build with only the Go toolchain.
