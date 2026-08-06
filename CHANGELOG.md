# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `make clean` now removes the release artifacts. It ran `rm -rf bin dist`,
  targeting a top-level `dist/` that GoReleaser stopped writing to when the
  build moved under `build/` — so it deleted the development binary, reported
  success, and left every packaged artifact in place.
- `scripts/build-all.sh` no longer deletes `build/targets.txt`, which is tracked,
  as a side effect of a release build.

### Changed

- **A bare `sshmgr` opens the interactive menu** when standard input is a
  terminal, instead of printing help. With any argument it is a plain CLI, and
  without a terminal it still prints help — a menu reading from a pipe would
  take whatever is on it as answers.
- Build output is consolidated under `build/`: `make build` writes
  `build/sshmgr` instead of `bin/sshmgr`, and `build/dist/` holds the release
  artifacts as before. There is no `bin/` any more.

## [3.0.0] - 2026-08-06

The Python implementation is gone from the tree, the verification matrix is
closed, and the documentation describes what ships.

Major rather than minor for two reasons, both below under **Changed**: the
`~/.ssh` layout moved, and `knownhosts init --user` was removed. Neither needs
action beyond running `reconcile` once — but a script that passed `--user` will
fail, and that is what a major version is for.

### Changed

- **`~/.ssh` layout.** One inline `config` holds every `Host` entry, grouped by a
  profile banner with `Host *` last, instead of a root config plus a per-profile
  file stitched together with `Include`. One hashed `known_hosts` replaces the
  per-profile trust stores; every line ssh-manager writes carries an `sshmgr`
  comment tag so it only ever prunes its own. `profiles/<name>/` now holds keys
  only. Identity isolation is unchanged and stronger: it comes from `IdentityFile`
  plus a **per-host** `IdentitiesOnly yes`, which the rendered config states
  explicitly for every host. Run `reconcile` once and the old files are migrated.
- `known_hosts` is mode 0600, not 0644. ssh has never needed the trust store
  world-readable, and its contents are an inventory of every host you connect to.
- A `key_name` may now repeat across profiles. v1 rejected that manifest; one
  person working under two organisations uses the same file name in both, so the
  ban prevented a normal setup. A key's identity is the pair `profile/key`.
- **`knownhosts init` no longer takes `--user`.** There is one store now, so
  there is nothing left for it to select — but the flag existed in 2.0.0, so a
  script that passes it will fail rather than being ignored. Drop it; `--all`
  covers every host in the manifest, which is what `--user` aggregated.

### Added

- `key add`, `key list`, `key delete` — declare, mint and remove a key
  independently of the host that uses it, with a guarded delete that refuses
  while any host still resolves to it.
- `show <selector>` — reconciles the manifest, the key files, the rendered config
  and the trust store in one view, because an auth failure is usually a
  disagreement between them.
- `clean [--dry-run] [--adopt]` — prunes stale pins and inventory records left
  behind by deletions.
- `doctor --strict` — escalates every dangling-key state to fatal, for CI.
- `--yes` on the destructive verbs, so they are usable from a script, and
  `--no-key-backup` to accept an overwrite that cannot be undone.
- `SSH_MANAGER_OLD_KEY_MAX_AGE_DAYS` — when an archived predecessor is called stale.

### Fixed

- **Rotation could lose a key on a crash.** Commit renamed four files with no
  rollback; an interruption between them left the tree without a usable pair.
  Rollback was worse: it deleted the live pair before moving the predecessor in.
  Both now preserve by hard link and rename over atomically.
- **`keygen --force` destroyed same-named keys in other profiles.** The overwrite
  set was keyed by bare name, so confirming one key regenerated every key that
  shared its name — silently invalidating identities the user was never asked
  about.
- **`init --force` could reset the manifest while reporting a backup it never
  wrote.** Every error from the backup copy was swallowed. A failed backup now
  stops the reset.
- **`migrate` flattened symlinks into world-readable copies** when the legacy
  home and the new one were on different filesystems. Symlinking a config file
  out to a dotfiles repo is ordinary; the migration left the user editing a stale
  copy.
- **A locked password store stayed locked.** `cmd:` secret lookups memoised
  failures, so unlocking and retrying returned the same empty token for the life
  of the process — invisible in a one-shot run, permanent in the TUI.
- **The TUI froze on the second mutating action of a session.** The advisory lock
  is per file descriptor, so a second acquire in one process waited forever on a
  lock that process already held.
- **A crafted `authorized_keys` line could panic the tool** on 32-bit builds
  (386, armv6, armv7 all ship): an attacker-controlled length prefix was bounds-
  checked in `int`, where it wraps.
- `sshmgr view` could pair one inventory record's fingerprint with another's
  status, expiry and deployments when two records pointed at the same key path.
- `sshmgr diff` counted a shared key once per host that used it.
- `import` reported more hosts than it wrote when a config repeated a `Host` block
  — which is what appending to a config rather than editing it produces.
- `sshmgr clean` dropped the inventory record of a key that had merely become
  unwired, leaving the key on disk with nothing tracking its expiry.
- `manifest.json` and `inventory.json` claimed atomic persistence while using a
  truncating write, and kept whatever mode the file already had — so a manifest
  loosened once stayed loose through every later save.
- The TUI menu, the passphrase prompt and `notify test`'s diagnostic reached past
  the command to the process's own streams, so a caller that redirected them was
  ignored.
- `host edit`'s flags, and `--provider`, `--token-env` and `--key-name` on
  `host add`, had no help text at all.

### Security

- Passphrases reach `ssh-keygen` through the askpass protocol rather than the
  command line, where any local user could read them from the process list.
- `authorized_keys` parsing rejects an oversized wire-format length prefix
  instead of trusting it.
- The shipped example `config/manifest.json` no longer contains real
  infrastructure. It held three live addresses, a university host with its login
  name, and the VPN endpoint fronting it — a target list, published as
  documentation.
- CodeQL scans Go. It was configured for Python, so the Go code had never been
  analysed.

### Removed

- The Python implementation and its test suite, preserved at the `python-final`
  tag. The binary has had no interpreter since 2.0.0; this removes the parity
  reference that was still in the tree.
- The `.build/` shell harnesses. Their assertions are Go tests now, so they run on
  every platform instead of macOS alone — and the last executing Python in CI
  went with them.

## [2.0.0] - 2026-06-17

ssh-manager is **rewritten in Go** as a single self-contained binary - no Python
runtime to install. Behavior is unchanged: the same `manifest.json` /
`inventory.json` / `providers.json` formats, the same `~/.ssh` layout and
managed-block markers, the same `sshmgr` command surface and `SSH_MANAGER_*`
environment variables. A v1 home works as-is.

### Changed

- **Pure Go, no Python.** Every verb (init, import, migrate, reconcile, keygen,
  config, diff, validate, doctor, profile, host, providers, net, knownhosts,
  snapshots, bundle, restore, recover, load, deploy, rotate, rollback, list,
  view, expiry, audit, notify, tui) is native Go. The binary is a ~10 MB static
  executable with no embedded interpreter (was ~30-50 MB with a frozen CPython).
- **More platforms.** Cross-compiles to macOS (Apple Silicon **and Intel**),
  Linux (amd64/arm64), and Windows (amd64) from a single build - Intel mac, which
  the bundled-CPython build couldn't ship, is supported again.
- Provider key management (GitHub `gh`, GitLab `glab`, DigitalOcean / Vultr /
  Hetzner / Linode / Scaleway REST, and a config-driven generic REST), the age
  bundle/restore, the desktop notifier, and the scheduled job (launchd / systemd /
  cron / schtasks) are all reimplemented natively. Bundles and `~/.ssh` snapshots
  remain interoperable with v1.

### Notes

- The list/view/expiry views now print plain text rather than the v1 `rich`
  tables; the data shown is the same.
- The v1 Python implementation remains available at the `v0.1.0` tag and as the
  parity reference in `src/`. (Since removed - see Unreleased. The reference is
  now the `python-final` tag.)

## [0.1.0] - 2026-06-16

First public release. ssh-manager manages SSH keys and `~/.ssh/config` from a single
manifest - reproducible output, profile-based isolation, and safety guarantees
(atomic writes, advisory locking, snapshot-before-mutate, load-bearing perms).

### Added

**Core lifecycle**

- **One per-user home in the OS-standard config location** holds all of a user's
  state - config (`manifest.json`, `inventory.json`, optional `providers.json`),
  secrets (`.env`, `age-identity.txt`, 0600), logs (`log/audit.log`), `snapshots/`,
  and transient `.state/`. The home is `$XDG_CONFIG_HOME/ssh-manager` (else
  `~/.config/ssh-manager`) on Linux/macOS and `%APPDATA%\ssh-manager` on Windows;
  `$SSH_MANAGER_HOME` (alias `$SSH_MANAGER_CONFIG_DIR`) overrides it, and a legacy `~/.sshmgr`
  is auto-migrated. No project-local `./config` mode. `~/.ssh` is unchanged.
- **Layered config, manifest-first.** The manifest is the source of truth, read
  from your home (`init` seeds an empty one). The provider catalog uses your
  `<home>/providers.json` if present, else the full default catalog shipped with
  the package (kept byte-identical to the repo `config/providers.json`) - so
  providers work out of the box and you only create your own file to customize.
- `init` creates and **converges** the home: every run (re)creates the directory
  structure + re-asserts perms and seeds missing files, without touching your
  existing config/secrets. `init --force` resets the seed files to defaults (in place); add `--backup` to
  copy the old ones into `<home>/.state/` first. `init` no longer seeds
  `providers.json` (the shipped catalog is the default); the `.env` template ships
  as package data.
- `migrate [--force]` - guided move of a legacy `~/.sshmgr` to the standard home
  for the stranded both-exist case (auto-migration handles the simple case).
- `doctor --json` - machine-readable report for scripting/monitoring; `doctor`
  also reports the active provider-catalog source and a stranded legacy home.
- **Secret-at-rest indirection.** Any provider `token_env` value may be
  `cmd:<command>` - the token is fetched at use-time from a secret manager
  (1Password, OS keyring, `age`, ...) instead of sitting in `.env` plaintext.
- `init`, `reconcile` (with `--dry-run`), `keygen` (with `--force` to overwrite
  existing keys - prompted, and snapshotted first), `config check/render/show`,
  `import` (onboard an existing `~/.ssh`), and `diff`.
- Profile-based layout: each identity's keys, rendered config, and its own
  `known_hosts` live under `~/.ssh/profiles/<profile>/`; `IdentitiesOnly yes` and
  a per-profile `UserKnownHostsFile` keep profiles from bleeding into each other.
- A single config renderer drives `render`, `check`, and `reconcile`; perms are
  load-bearing (700/600/644) and every state write is atomic under an advisory
  lock. Key generation never clobbers an existing private key unless you ask.

**Deploy & providers**

- `deploy` over a pluggable provider strategy (config-driven via the provider
  catalog - your `<home>/providers.json` or the shipped default): GitHub and GitLab (CLI + token, cloud and
  enterprise/self-hosted); Bitbucket, Gitea, Codeberg, Forgejo, Gogs, SourceHut,
  Azure DevOps, and AWS CodeCommit (web-panel); cloud-VPS account keys for
  DigitalOcean, Vultr, Hetzner, Linode, and Scaleway (REST); and `generic-ssh`
  (`ssh-copy-id` / hardened `authorized_keys` editing). Any REST key API can be
  added with no code via `kind: rest`. Without a token, providers degrade to
  printing the dashboard URL.
- `validate` checks every managed keypair (both keys parse, the public key is
  derived from the private and matches, perms are correct); `providers` lists the
  active catalog and whether each credential is set, and `providers --export`
  materializes an editable copy of the shipped catalog into the home.
- **Network/VPN awareness.** Hosts can be marked `requires_vpn` (with optional
  `vpn_name` + `vpn_url`). `net` shows per-host connection status + a VPN
  indicator, and `deploy`/`rotate` run a bounded SSH-level reachability probe
  first - so a host that's down or behind a disconnected VPN (including a `:443`
  host that accepts TCP but never speaks SSH) fails fast with "connect the VPN at
  <url> and retry" instead of hanging. Every `ssh` / `ssh-copy-id` call is also
  hard-timeout-bounded.
- `doctor` prints the resolved home (the OS-standard dir or `$SSH_MANAGER_HOME`) and `~/.ssh`,
  so it's always clear where state lives.

**Rotation, expiry, backup, recovery**

- `rotate` - zero-downtime, stage → deploy → verify → archive (at most one
  predecessor kept) - and `rollback`.
- `expiry` with an inline banner and a scheduled desktop notifier; `audit` of
  deployments, hygiene, and recent activity.
- `bundle` / `restore` - `age`-encrypted, off-machine backup with true same-key
  recovery; the `.env` is never included.
- `snapshots` - every mutating command snapshots `~/.ssh` first, so any run is
  reversible with one command.
- `recover` - a break-glass snippet (or full interactive tool) to paste into a
  provider console when you're locked out entirely.

**Editing, agent, trust, UI**

- `profile` and `host` add/edit/delete (deletes can revoke + prune); `load`
  (`ssh-add`, Keychain on macOS); `knownhosts init` (initialize trust stores -
  create the file + pin reachable hosts, with a per-store report - scoped to a
  profile, `--all` profiles, and/or `--user` for the per-user `~/.ssh/known_hosts`)
  and `knownhosts pin` (host-scoped, fingerprint-confirmed, via `ssh-keyscan`);
  and an interactive `tui`.
- `--yes`/`-y` on destructive verbs (plus `--revoke` on the deletes) for
  non-interactive / scripted use.

### Platforms

- **macOS**, **Linux**, and **Windows** are all first-class. macOS/Linux: launchd /
  systemd-user-or-cron schedulers, Keychain / `notify-send`, `UseKeychain` on macOS
  only. Windows: `icacls` owner-only ACLs, `schtasks`, PowerShell toast - validated
  by real-binary tests **and a full reconcile/perms/config e2e** on the
  windows-latest CI runner.

### Security & robustness

- **Manifest input is hardened.** Names that become filesystem paths (profile,
  alias, key_name) reject `/`, `\`, `..`, leading `-`, whitespace, glob `*?`, and
  control chars; hostname and user reject whitespace, newlines, and leading `-`;
  `raw_options`/`global_options` reject command/code-executing keys (`ProxyCommand`,
  `LocalCommand`, `Match`, `Include`, `KnownHostsCommand`, `PKCS11Provider`,
  `SecurityKeyProvider`). `key_scope` is enum-validated. Closes config-injection /
  path-traversal / wildcard-hijack from a hand-edited or imported manifest.
- **Corrupt inputs fail cleanly, not with a traceback** - corrupt inventory,
  snapshot, or bundle (and a wrong-shape `providers.json`) raise a clear error; this
  matters most on the recovery paths. `validate <unknown>` now errors instead of
  silently passing.
- **No hangs / truncation on the network path** - `gh`/`glab`/`ssh-keyscan` calls
  are timeout-bounded; Linode/Scaleway key listing errors rather than silently
  truncating; REST `kind: rest` requires `https://`.
- **Perms/secrets** - `manifest.json`/`inventory.json` written 0600; snapshot/restore
  refuse a symlinked `~/.ssh`; the audit log redacts secret-named fields; scheduled
  jobs handle executable paths containing spaces.

### Fixed

- **Robust legacy-home migration.** The `~/.sshmgr` to standard-dir move is now
  serialized under an advisory lock with a re-check, and uses `os.rename` (which
  errors rather than nesting the legacy dir inside an existing destination) - fixing
  a TOCTOU race; a genuine failure is surfaced to stderr and flagged by `doctor`
  (which now also shows a stranded legacy home and the active provider-catalog source).
- **Consistent resolution + catalog perf.** `XDG_CONFIG_HOME`/`APPDATA` are read from
  the same env mapping as the `$SSH_MANAGER_HOME` override (no split between a passed env
  dict and `os.environ`); the provider catalog is memoized by path+mtime and `list
  --type`/category lookups honor the shipped-default fallback (no per-host re-parse).
- **Cross-profile `key_name` collision rejected.** Two profiles reusing one
  `key_name` (e.g. two `shared` profiles both named `deploy`) would make rotate/
  deploy mint into one profile's dir but act on the other's hosts (orphan/lockout).
  The manifest now rejects a `key_name` owned by more than one profile at load.
- **Per-profile trust on deploy/verify/rotate.** `ssh`/`ssh-copy-id` in deploy,
  login-verify, and rotation now use the host's per-profile `known_hosts`
  (`UserKnownHostsFile`), not the default `~/.ssh/known_hosts` - so a key is
  verified against the SAME store `ssh <alias>` uses, and TOFU lands the host key
  in the right per-profile store (isolation no longer bypassed by network ops).
- **Profile named `old` no longer hidden from expiry/audit.** Archived
  predecessors are detected by path structure (`profiles/<p>/old/<name>`) instead
  of a bare `/old/` substring, so a profile literally named `old` is tracked.
- **TUI** gained a "Pin host keys (known_hosts)" action (it had no way to set up
  trust, yet that's required for the first connection). `knownhosts init --force`
  is documented accurately (re-scan + add new keys; never silently replaces a
  changed host key).
- **GitLab adapter parity.** `gitlab` now lists keys via `glab api user/keys`,
  so deploy is idempotent (a key already on the account isn't re-added/errored)
  and `verify`/`remove` match by key body - rotation can verify and revoke GitLab
  keys instead of always aborting or leaving the old key live (mirrors the GitHub fix).
- **Robustness.** A manifest/inventory path that is a directory or unreadable now
  raises a clean error instead of a traceback; a `known_hosts` that is a directory
  no longer crashes `doctor`/auto-pin. `doctor` flags the same Host alias used in
  more than one profile (ssh applies the first match, silently shadowing the rest).
  `SSH_MANAGER_AUTO_PIN` accepts `0/false/no/off`; the auto-pin reachability probe is
  short (it runs under the lock); the HTTP redirect guard no longer drops the token
  on a same-host `:443`-explicit redirect; `known_hosts` `@cert-authority`/`@revoked`
  lines are recognised.
- **Auto-pin known_hosts on reconcile/keygen.** After minting keys, each profile's
  `known_hosts` is created/updated for the hosts it can reach (trust-on-first-use;
  never overrides an existing pin, skips unreachable/VPN-gated hosts). Disable with
  `--no-pin` or `SSH_MANAGER_AUTO_PIN=0`; `knownhosts pin` remains the fingerprint-verified
  path. This removes the "fresh reconcile -> git push fails host-key verification"
  footgun for reachable hosts.
- **Multi-identity guidance.** Documented that hosts sharing one server (e.g. two
  GitHub accounts on `github.com`) should use distinct, profile-prefixed **aliases**
  (`github-personal`, `github-simtabi`) to avoid collisions, and that the SSH `user`
  for GitHub/GitLab/Bitbucket must stay `git` (the key selects the account; a custom
  user breaks `git@host:` remotes). The shipped example manifest uses the prefixed form.
- **Unpinned host keys are now discoverable.** With per-profile
  `UserKnownHostsFile` and OpenSSH's default `StrictHostKeyChecking ask`, a host
  that hasn't been pinned fails non-interactive `git`/`ssh` with "Host key
  verification failed". `doctor` now lists each reachable manifest host lacking a
  pinned key with the remedy (`sshmgr knownhosts pin --all`), and `reconcile`/
  `keygen` print the pin+deploy steps after minting. Docs document the
  reconcile -> pin -> deploy first-use sequence.
- **`~/.ssh/config` foreign content is preserved.** `reconcile`/`config render`
  now rewrite only the marked ssh-manager block (`# Managed by ssh-manager ...` to
  `# End of ssh-manager-managed block ...`) and keep anything above/below it verbatim -
  so a tool-injected preamble such as OrbStack's top-of-file `Include`
  (which it won't re-add if removed) survives a re-render. `config check` no longer
  flags the preserved content as drift. One composer backs both write and check.
- **GitHub/GitLab enterprise & key removal.** `gh`/`glab` are driven by their
  environment (`GH_HOST`/`GH_ENTERPRISE_TOKEN`, `GITLAB_HOST`/`GITLAB_TOKEN`),
  not a nonexistent `--hostname` flag, so enterprise/self-hosted instances work;
  GitHub key listing/removal go through `gh api user/keys` and match by key
  **body** (never by title), so rotation can't revoke the freshly deployed key.
  GitHub deploy is now idempotent.
- **Shared-key delete.** Deleting one host that shares a key revokes it from
  *that* host's target only and keeps the inventory record (and per-host history)
  for the hosts that remain; deleting the profile revokes *every* host (previously
  only the first).
- **`deploy` exit code.** Exits non-zero on any failed deploy (provider/API error
  or unreachable host), not only "unreachable"; a manual/web-panel paste still
  exits 0. Errors and warnings now go to stderr.
- **`import` is non-destructive.** Refuses to replace a non-empty manifest unless
  `--force` (which backs up the previous manifest + inventory first); multi-pattern
  `Host` lines bind to all aliases, `Match` blocks terminate cleanly, and
  code-executing directives are dropped instead of aborting the import.
- **Rotation.** A rotated-in key inherits the requested passphrase
  (`rotate --passphrase`); an aborted rotation pulls the staged key back off any
  target it reached; repeated rotations no longer accumulate stale `/old/`
  inventory records; VPS key titles are body-stamped so providers that enforce
  unique names (Hetzner) accept the staged key.
- **REST / HTTP.** A generic `kind: rest` provider raises instead of reporting a
  phantom success when delete/rename aren't configured; the HTTP client converts
  read-phase transport errors to a clean error, strips credentials on cross-origin
  redirects, refuses an `https -> http` downgrade, and honors `Retry-After`.
- **Permissions.** Restored private keys and snapshot tarballs are created
  owner-only (no world/group-readable window); Windows `icacls` strips broad
  principals; the Windows scheduled task is quoted for `cmd.exe`.
- **Other.** `knownhosts pin <alias>` resolves the manifest hostname/port; a
  malformed date in a hand-edited inventory no longer crashes `expiry`/`audit`;
  the JSON schemas accept the nullable fields the tool actually writes; the
  package version has a single source (`src/ssh_manager/__init__.py`); `--version` flag
  added.

### Quality

- Typed throughout (`mypy --strict`), linted (`ruff`), and covered by a unit
  suite plus an end-to-end smoke (`make e2e`). Output uses **rich**, prompts use
  **questionary**, the CLI is **typer** - one toolkit per concern.
- CI runs the suite on macOS / Linux (Python 3.11-3.13) and the platform layer on
  Windows, plus CodeQL, secret scanning (gitleaks), and pre-commit. Releases
  build and attach artifacts to a GitHub Release on a `v*` tag.

[Unreleased]: https://github.com/simtabi/ssh-manager/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/simtabi/ssh-manager/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/simtabi/ssh-manager/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/simtabi/ssh-manager/releases/tag/v0.1.0
