# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`key_comment` - choose the comment new keys carry.** A template on `defaults` or on a profile, with
  `{profile}`, `{alias}`, `{key}`, `{date}` and `{device}`; unset keeps `{profile}/{alias} {date}`, the comment
  every earlier release wrote. `profile add|edit --key-comment` sets it (`""` clears it on edit), and the manifest
  schema lists it. It applies to keys minted from then on; an unknown placeholder is refused on load.
- **`profile add --key-scope`**, the flag `profile edit` already takes.

### Changed

- **`termius keys ALIAS` finds a git host without `--include-git`.** Naming the host is the choice; the flag now
  only widens the list. `--skip` still leaves a named host out.
- **Restore checks a key in a rendered slot by parsing it.** It used to lay down any file that began `ssh-` or
  `-----BEGIN `; it now reads the public key's wire format, or the private key's PEM block and nothing after it
  (an OpenSSH key through its clear public half, so a passphrase-protected key still passes).

### Fixed

- **A rotated key's inventory comment matches the key.** The record said `profile/<key name> date` while the
  new `.pub` said `profile/<alias> date`; both now come from the same template.

### Deprecated

- **`profile add --shared`**, in favour of `--key-scope shared`. It still works, prints a deprecation notice, and
  is hidden from `--help`; it will be removed no earlier than 4.0.0.

## [3.5.0] - 2026-10-26

### Added

- **`sshmgr termius keys [ALIAS]` - get each key into Termius.** Termius's CSV import has no key column, so imported
  hosts stop at SSH key selection. With no alias it lists every exported host with its Termius key label (the key
  file's name) and private key path; with an alias it copies that host's private key to the clipboard (pbcopy,
  wl-copy/xclip/xsel, or clip) and prints the label to paste into Keychain → New Key. The key is never printed unless
  `--print` is given (with a stderr warning); `--clear` and `--clear-after DUR` empty the clipboard; `--include-git`
  and `--skip` select hosts as on `termius export`. `termius export`
  now points to it, and the export docs and Termius recipe describe the full flow with Termius's docs as sources.
- **`sshmgr host apply` - add or update hosts from compact specs.** A spec is
  `<alias> <host>[:port] <user> [role]`, e.g.
  `sshmgr host apply adelsaiq dani-prd-web-00 206.189.185.129 ploi web`. Give
  one positionally, many with repeated `--host "..."`, or a file with
  `-f FILE` (`-` for stdin; one spec per line with `#` comments, or a JSON
  array of spec strings or `{alias,host,user,port,role,tags}` objects). A new
  alias is added the way `host add` adds it; an existing one has its hostname,
  user and port updated the way `host edit` does, and the role and any `--tag`
  are merged into its tags (never removed). Each host is reported added,
  updated (with what moved) or unchanged, so re-running the same specs is a
  no-op. The batch passes the manifest's validation and is saved at once, so
  one bad spec changes nothing. `--create-profile`/`--category` create a
  missing profile (and are undone if the batch is refused, so no empty
  profile is left behind), `--reconcile` mints the new keys afterwards, and
  `--dry-run`/`-y` behave as on `reconcile`.

- **`sshmgr host edit --tag` and `--untag` - change a host's tags.** Tags could be set by `host add` and merged
  by `host apply`, but nothing took one off. `--tag` (repeatable) now replaces the host's tags, `--tag ''` removes
  them all, and `--untag` (repeatable) removes one after any `--tag`; a tag the host lacks is ignored. Without either
  flag, `host edit` leaves tags alone, as before.
- **`doctor` reports the tools the manifest relies on.** A VM host whose hypervisor CLI is not on PATH, and `git`
  missing once `defaults.git` is set, are listed as `MISSING tool` and fail the verdict (JSON `needed_tools`): both
  stop a connection or a `sshmgr git` command that the rest of the report calls healthy. A missing clipboard tool is
  reported as advice (JSON `clipboard`), since `termius keys --print` works without one.

### Fixed

- **An alias, hostname or user that ssh refuses is rejected when it is added.** `host add`, `host apply` and
  `import` accepted shell metacharacters such as `;`, `&`, `|`, `$` or backticks, which ssh refuses at connect time
  ("hostname contains invalid characters"). The host could never connect, and `config check` failed for every host
  because `ssh -G` stopped on it. Validation now refuses the characters OpenSSH's own `valid_hostname` refuses in the
  alias and hostname, and those `valid_ruser` refuses in the user (`$` and `\` stay allowed there, for `DOMAIN\user`).
  A manifest that already holds such a value no longer loads, so the error now names the file, the profile and the
  host to fix, and `import` skips a refused host and reports it instead of refusing the whole config.
- **`restore` reports a config it could not re-render.** The bundle no longer carries the rendered files, so a
  restore whose manifest failed to load left `~/.ssh` without its category configs while reporting success. It now
  exits non-zero with the reason after listing what it restored.
- **`--help` no longer shows a backticked phrase as a flag's value name.** pflag reads the first backticked word of a
  usage line as the value's name, so `--provider`, `--proxy`, `--vm` and `termius keys --include-git` printed as
  e.g. `--provider sshmgr providers`. A test now walks every flag.
- **`reconcile` no longer claims to fix permissions it did not change.** The
  fixer counted every managed path it visited, so an already-correct tree
  printed `perms fixed on 53 paths` on every run, indistinguishable from real
  drift. It now counts only paths whose mode actually changed and prints
  `perms: ok` when there were none. Nothing was resetting modes between runs.
- **The git ssh mode `Host github.com` block is rendered once, with its
  profile.** When `defaults.git.profile` is filed under a category, the block
  now goes into that category's `profiles/<category>/config` instead of the
  root `~/.ssh/config`. The category Include still precedes `Host *`, so ssh
  resolves `github.com` exactly as before. It is also skipped when a host is
  already aliased `github.com`.
- **`config check` reports duplicate Host blocks.** A `Host` pattern the
  managed files define more than once is listed as `DUPLICATE` (ssh only reads
  the first) and the config is not reported in sync.
- **OrbStack's Include is moved to the top.** OrbStack appends
  `Include ~/.orbstack/ssh/config` to the end of `~/.ssh/config` and says it
  only works at the top; a render now moves that line (with its comments) to
  the top of the file. No other foreign content moves.
- **Releases carry their notes again.** `changelog: disable: true` made
  GoReleaser skip the pipe that reads `--release-notes`, so v3.2.0 and v3.4.0
  were published with empty bodies while the run reported success. The config
  no longer disables it, the release workflow sets the body from the tagged
  CHANGELOG section after GoReleaser as a backstop, and a test fails if either
  regresses.

## [3.4.0] - 2026-10-24

3.3.0 was never tagged; its changes (git remote modes, devboxes) ship in this release.

### Added

- **Cloudflare Access hosts.** `sshmgr host add|edit ... --proxy cloudflared`
  (manifest `proxy: {kind: cloudflared}`) renders
  `ProxyCommand "<cloudflared>" access ssh --hostname %h`, so `ssh <alias>`
  reaches a server through Cloudflare Access with no SSH port open. `doctor`
  reports a proxied host when `cloudflared` is not installed; the Termius export
  skips it, since Termius ignores ProxyCommand.
- **Exports for other tools.** `sshmgr config export --flat` writes the whole
  config as one file, every host inline with absolute key paths and no
  `Include` or `Match`, for a tool that reads a single `ssh_config`.
  `sshmgr termius export` writes a Termius CSV import (group = profile,
  label = alias, tags, address, port, user; never a password) and lists the key
  to attach to each host; `--open` opens Termius and shows the file on macOS,
  `--skip` leaves a host out, and VM and git hosts are left out and reported.
  Both write under `~/.config/ssh-manager/exports/` (0600) and refuse any target
  inside `~/.ssh` (checked by inode, so case and symlinks cannot get round it),
  so the split config, keys and trust store are never changed.
  Termius's own importer reads only the top-level `~/.ssh/config` and never
  saw the hosts in category files.
- **Git remote modes.** `sshmgr git status` shows how each checkout's GitHub
  origin authenticates; `sshmgr git use profile|ssh|https [PATH...]` switches it:
  the profile's own alias (`git@github-<profile>:owner/repo.git`, the default),
  plain `git@github.com` through a rendered `Host github.com`, or HTTPS through
  your credential helper. The mode comes from the argument, `--mode`,
  `SSHMGR_GIT_MODE`, then `defaults.git.mode`; the owner picks the profile through
  `defaults.git.orgs`, then `defaults.git.profile`, and several candidates are an
  error rather than a guess. Each new URL must pass `git ls-remote` before origin
  is rewritten; `--dry-run` changes nothing.
- **Devboxes.** A host with `vm: {hypervisor, name}` is a local VM:
  its block renders `ProxyCommand "<sshmgr>" vm proxy <alias>`, which asks
  Parallels, VMPal, VMware, UTM or Lima for the VM's current address on each
  connection and starts a stopped VM. `sshmgr vm list` shows every installed
  hypervisor's VMs (OrbStack and Podman included, which keep their own SSH and
  keys), `vm add` adds one as a host, and `vm docker-context` creates an
  `ssh://<alias>` Docker context.
- `doctor` fails when a rendered VM ProxyCommand names an sshmgr binary that no
  longer exists (`stale_proxy` in `--json`); `config render` rewrites it.

### Fixed

- **Audit of 2026-10-21: security.** Dev mode no longer lets `rotate`,
  `rollback`, the TUI deploy or `--revoke` reach real servers, and dev-mode
  `migrate` no longer moves the real `~/.sshmgr` into the sandbox. `restore`
  lays down only the members `bundle` writes, so a forged bundle cannot replace
  `authorized_keys` or `config`. Option keys must be bare ssh keywords
  (`ProxyCommand=x` and `"ProxyCommand "` bypassed the dangerous-option check)
  and `XAuthLocation` is refused. Caller headers are dropped on a cross-origin
  redirect, and a pagination link that leaves the API origin is refused rather
  than sent the token. Import splits `Keyword=value`, so `ProxyCommand=...`
  is dropped like the plain form.
- **Audit of 2026-10-21: correctness.** A rollback checks every server before
  moving a key and swaps the pair into `old/`, so an unreachable target no
  longer destroys the rotated-in key, and an incomplete rollback exits non-zero.
  Mutating commands take the lock before reading state, so concurrent runs no
  longer drop each other's inventory records. Hostnames match known_hosts
  case-insensitively (`clean` had pruned a live pin) and `@revoked` lines no
  longer count as pinned. Aliases, hostnames and users that ssh reads as syntax
  (`"`, `'`, `#`, `!`, `,`, `=`) are refused, and `config check` fails when ssh
  cannot parse the config. Import resolves hosts the way ssh does: first value
  wins, `Host *` applies, quotes are removed, and the same alias in two
  profiles imports once instead of saving an invalid manifest. 1Password
  rollback works after a second vault rotation. Keys minted before a failed
  mint, keys on disk with no record, and the key `keygen --force` replaces all
  keep their inventory records; `deploy` records the manifest's key type and
  rotation. `rotate <profile|alias>` works, a shared profile needs a key name,
  and an unknown command is reported ahead of its flags.
- **Audit of 2026-10-21: what ssh would not use.** `config check` and `doctor`
  report a hand-written Host block above the managed block that shadows a
  managed alias (ssh reads it first), instead of calling the config in sync;
  sshmgr still never edits content outside its block. A raw option that repeats
  a line sshmgr writes (HostName, User, Port, UserKnownHostsFile) is no longer
  rendered as a second, ignored line, and `doctor` names the field to use. A
  `snapshots restore` keeps a `.pub` that would not match the private key on
  disk, says so, and now works in dev mode.
- **Bundles no longer carry rendered config.** `bundle` leaves out the
  `profiles/<category>/config` files and legacy `profiles/*/known_hosts` that
  sshmgr renders, and `restore` skips them in older bundles (naming each) and
  re-renders from the restored manifest. Before, a forged bundle could lay down
  a category config with a ProxyCommand, which `~/.ssh/config` Includes. A key
  that happens to be named `config` is still bundled and restored.
- **Hosting panel targets no longer force an unverified rotation.** A
  `ploi`, `forge` or `cpanel` target only accepts a pasted key, and `rotate`
  either aborted or, with `--allow-unverified`, committed before the key was
  pasted, so SSH to that server failed until it was. At a terminal, `rotate` now
  shows the staged public key and where it goes, waits for the paste, and logs
  in with the staged key; only a working login counts as verified. The committed
  report says where the old key still has to be removed. Without a terminal,
  nothing changes.
- `knownhosts pin` reported `pinned 0 host key(s)` and exited 0 for a host that
  returned no SSH key (a closed port, or a web server on 443). It now names each
  such host with the reason, pins the rest, and exits non-zero; a missing
  `ssh-keyscan` is reported too.
- The manifest JSON schema rejected `category`, `key_store`, `op_vault`, `keys`
  and `onepassword_agent`, which the code accepts; it now lists every field, and
  a test compares the two.
- The `knownhosts` docs and feature catalog still described per-profile trust
  stores at mode 0644; there is one hashed store at 0600.

## [3.2.0] - 2026-10-19

### Added

- **Keys can live in 1Password.** A profile with `"key_store": "1password"` and
  an `op_vault` keeps its private keys as SSH Key items in that vault, created
  with the `op` CLI; only the public halves are written to disk. Its hosts render
  `IdentityFile <key>.pub` and `IdentityAgent` pointing at the 1Password agent.
  `rotate` stages the replacement in the vault, verifies it through the agent,
  and keeps one `<key>.old` predecessor; `rollback` restores it. Items are
  archived, never deleted. Rotating a key after switching its profile to
  `1password` moves it into the vault. `validate` checks the item matches the
  `.pub`, and `doctor` checks for `op`, the agent socket, and that the agent
  serves each vault (`agent.toml`). Two 1Password profiles may not keep the same
  key name in one vault, and 1Password keys must be `ed25519`.
- **Batch rotation.** `rotate` accepts several keys, profiles or host aliases,
  `--category <name>`, or `--all`, with `--dry-run` to list the batch. One
  confirmation, backup and snapshot; each key rotates on its own, so one failure
  leaves only that key as it was.
- **`key regen-pub`** rebuilds `.pub` files from the private key, or from the
  vault item for a 1Password profile, for the same selections. It reports each
  key as unchanged, created or rewritten, and never touches a private key.
- **`op://` secret references.** A provider token whose value starts `op://` is
  read with `op read`, beside the existing `cmd:` form.
- **Profiles can be grouped into categories.** A profile with `"category":
  "clients"` keeps its keys under `profiles/clients/<profile>/` and renders its
  `Host` blocks into `profiles/clients/config`, which the root config Includes
  under `Match all`. `profile add` and `profile edit` take `--category`; the edit
  moves the key directory and re-points inventory records, or only the records
  when the directory was already moved by hand. Profiles without a category, and
  every existing manifest, render exactly as before.

### Fixed

- **The install command could not fetch its script.**
  `https://opensource.simtabi.com/install/ssh-manager` — the URL in the README,
  the docs and the installers' own usage lines — returns 404, and always has;
  that portal subtree was never published. Both install commands now point at a
  URL that resolves, and a test asserts every documented raw URL names a file
  this repository actually ships. The install scripts are also uploaded as
  release assets, so a future release carries them alongside the binaries.
- **`curl … | bash` failed outright on a stock Mac.** The installer expanded an
  empty array under `set -u`, which bash 3.2 — still what macOS ships as
  `/bin/bash`, and what `#!/usr/bin/env bash` finds there — rejects as an unbound
  variable. It died before downloading anything, for everyone without
  `GITHUB_TOKEN` set (which made the array non-empty and hid it). A second bug in
  the same six lines piped `curl` into `grep -m1`: grep closes the pipe on its
  first match, curl exits 56, and `pipefail` turns that into a failed install.
  CI now runs the installer on every non-Windows runner, so the macOS job
  exercises bash 3.2 — neither bug is a syntax error, so shellcheck saw neither.
- The PowerShell installer matched its checksum line by unanchored substring.
  `checksums.txt` lists a binary, its archive and the archive's SBOM, so a bare
  name matches three lines and `-First 1` took whichever came first. Safe for the
  `.exe` names it asks for and nothing else, which is not a property to rest a
  checksum gate on; it is anchored on the filename field now, like the shell one.

### Removed

- **Every remaining reference to the previous implementation's language.** No
  source file mentions it, and neither do the docs, the test names or the tag
  names. Comments that compared behaviour to it now describe the behaviour —
  "the spelling v1 wrote for a true value" rather than a foreign function name —
  so they can be read without knowing what came before.

- **The last interpreter dependency.** `pre-commit` needs a runtime this project
  does not otherwise use, so CI carried a language-setup step and a job of its own
  to run four rules about whitespace. Its checks are kept, not dropped: `gitleaks` already ran as a
  separate job over the full history (which the hook could not do), `gofmt` and
  `go vet` are already in `make ci`, and the file-hygiene rules — trailing
  whitespace, final newline, LF endings, merge markers, oversized files, JSON
  validity — are now Go tests, so they run in `make check` too rather than only
  for people who had installed pre-commit. The interpreter-related entries in `.gitignore`,
  `.editorconfig` and `dependabot.yml` went with it.

### Changed

- **GitHub verify checks the account.** When a deploy's API token and an ssh
  login are both available, GitHub must greet the key as the account the token
  belongs to. A token for the wrong account (a personal token left in a machine
  user's variable) used to add the key there and pass verification.
- **`reconcile` refuses to mint a key that only changed directory.** A declared
  key found in the other layout (flat when the manifest says categorized, or the
  reverse) used to be planned as a fresh key, leaving two keys for one identity.
  It now stops and names where the key is. `doctor` reports such a key as
  untracked at its real path, and its missing finding no longer advises
  `reconcile`.
- **`config render` prunes only `profiles/*/config` files it owns:** those with
  the managed header, or in a flat profile directory (the v1 per-profile slot).
  A hand-written category file beside profile directories is left alone.
- Comments citing the previous implementation's source files are gone. They named
  paths that exist nowhere, and the ones that were resolvable required knowing a
  tag to resolve them. What each test asserts is now stated in the test.

## [3.1.1] - 2026-08-06

### Security

- **Restoring a snapshot or a bundle can no longer write outside its
  destination.** Both extractors validated member names and then checked that
  the joined path was textually inside the target — which a symlink already
  present in that target defeats, because the escape happens when the OS
  resolves the path rather than in how it is spelled. An archive with nothing
  but ordinary relative names could overwrite a file anywhere the user could
  write. Both now confine every write with `os.Root`, so containment is enforced
  by the kernel on the resolved path; the name validation stays, for a better
  error than a refused syscall. Reported by CodeQL as `go/zipslip` once the Go
  code was being scanned, and confirmed by a test that fails against the
  previous implementation.

## [3.1.0] - 2026-08-06

### Added


- **The interactive menu opens with a banner.** It names the binary and build
  (version, platform, commit, date), the config home and `~/.ssh` it will
  operate on, what it found there (profiles, hosts, keys), and the state of the
  tree: agent, config drift, `known_hosts` coverage, permissions, dangling keys
  and rotations due. Both locations are environment-overridable, so without them
  a session pointed at a sandbox and one pointed at a real tree were
  indistinguishable. Rows marked `!` carry the command that fixes them, and the
  banner is redrawn after any action that changes `~/.ssh`.
- **Dev mode: `--dev-root <dir>` (or `$SSHMGR_DEV_ROOT`) runs the whole tool
  against a scratch directory** instead of `~/.ssh`, so every verb that mints,
  renders or pins can be exercised without touching the tree you use. Previously
  impossible: the config home had `$SSH_MANAGER_HOME` but `~/.ssh` had no
  override at all, so the only option was moving `$HOME` — which also moves the
  ssh-agent socket and the launchd session. One root holding `ssh/` and
  `config/`, not two independent overrides, because the half-applied case looks
  sandboxed until it overwrites a real key. Announced on stderr by every command
  and led with in the TUI banner; `deploy` and `notify install` are refused,
  since neither takes effect inside a directory.
- `make ci-linux` runs the CI gate inside a Linux container on the Go version
  `go.mod` asks for. `make check` only tests the machine you are on and
  `lint-all` cross-compiles without running anything, so a Linux-only failure was
  invisible until CI reported it — and unreachable when CI could not.
- A project icon at `docs/assets/sshmgr.svg` — a single scalable mark for the
  docs site, the repository's social preview and a favicon.

### Changed

- **`make build` empties `build/` first, every time.** A stale binary is not
  hypothetical: a bug was reported against this tool from a binary built one
  minute before the fix landed, and it was indistinguishable from the fix not
  working. `make clean` now removes everything in `build/` except the files git
  tracks there, rather than the two paths it happened to know about.
- **The Go module moved to `src/`.** The repository now keeps its Go code under
  `src/` and its own files — README, LICENSE, CHANGELOG, `docs/`, `.github/` — at
  the root, with build output in a single root `build/`. Import paths become
  `github.com/simtabi/ssh-manager/src/v3/...`; `make` is unchanged and remains
  the supported way to build.
- **Each release is now tagged twice on the same commit.** `vX.Y.Z` drives the
  release as before; `src/vX.Y.Z` is how Go resolves a module that lives in a
  subdirectory, and the release workflow creates it, so you still tag once.
- **Every verb that changes `~/.ssh` now confirms first.** `reconcile`, `keygen`,
  `import`, `deploy`, `clean`, `config render`, `knownhosts init`, `migrate` and
  `notify install` ask before acting; the deletes and `rotate` already did.
  `reconcile` shows its dry run as the question. Each takes `--yes`/`-y`.
  The prompt appears only when standard input is a terminal — a script, cron job
  or CI step proceeds as before, because there is nobody to ask and declining on
  its own would be a silent no-op rather than a safeguard.
- **The interactive menu is grouped by consequence.** Ten flat entries put
  *Reconcile* one keystroke from *Expiry status* with nothing to say which of
  them wrote to disk; they are now under *Inspect*, *Change `~/.ssh`* and
  *Recover*. Each entry shows the CLI verb that does the same thing, and that
  verb is an accepted answer — `5`, `reconcile` and the full label all work.
  An unrecognised answer re-prompts instead of ending the session, and `q`
  quits.
- **A bare `sshmgr` opens the interactive menu** when standard input is a
  terminal, instead of printing help. With any argument it is a plain CLI, and
  without a terminal it still prints help — a menu reading from a pipe would
  take whatever is on it as answers.
- Build output is consolidated under `build/`: `make build` writes
  `build/sshmgr` instead of `bin/sshmgr`, and `build/dist/` holds the release
  artifacts as before. There is no `bin/` any more.

### Fixed

- **A `go install` build no longer reports the wrong version.** It applies no
  ldflags, so the binary fell back to the hardcoded `2.0.0-dev` — two major
  versions stale, from v3 sources, on the install path the README documents.
  Go already records the real version inside the binary; it is now read from
  there, along with the commit, build time and a `-dirty` marker for an
  uncommitted tree. Such a build also has no VCS stamp, so the commit and time
  are recovered from the pseudo-version, which already ends in both — it no
  longer calls itself a "dev build" while holding a published version.
- **`go install` works again.** The module declared
  `github.com/simtabi/ssh-manager` while being tagged `v2.0.0` and `v3.0.0`, and
  Go requires a major-version suffix from v2 onward — so it rejected both tags
  and fell back to the newest one it would accept, `v0.1.0` from before the rewrite,
  which contains no `cmd/sshmgr`. The documented install command has been
  failing since v2.0.0. The module path is now
  `github.com/simtabi/ssh-manager/src/v3`.
- `scripts/build-all.sh` no longer rewrites the tracked release matrix when
  given a `TARGETS=` override — building one target while iterating would have
  shrunk the next release to that single target. Its build loop also read
  `targets.txt` rather than the matrix it had just selected, so the override was
  ignored in any case where the two differed.
- `make feature-check` ran 9 tests, not the 80 in the package, because its
  `-run 'TestCommandSurface|TestVerbs'` regex did not match
  `TestTheCommandSurfaceMatchesTheOneItReplaced` — the one test that pins the
  command surface against the implementation it replaced. A target
  documented as "exercise every command with assertions" was excluding the
  assertion that matters most. It now runs the package.
- The pre-commit `gofmt` hook can now fail. It ran `gofmt -l`, which lists
  unformatted files and exits 0, so it reported problems and passed.
- `make clean` now removes the release artifacts. It ran `rm -rf bin dist`,
  targeting a top-level `dist/` that GoReleaser stopped writing to when the
  build moved under `build/` — so it deleted the development binary, reported
  success, and left every packaged artifact in place.
- `scripts/build-all.sh` no longer deletes `build/targets.txt`, which is tracked,
  as a side effect of a release build.


## [3.0.0] - 2026-08-06

The previous implementation is gone from the tree, the verification matrix is
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
- CodeQL scans Go. It was configured for the wrong language, so the Go code had never been
  analysed.

### Removed

- The v1 implementation and its test suite, preserved at the `v1-final`
  tag. The binary has had no interpreter since 2.0.0; this removes the parity
  reference that was still in the tree.
- The `.build/` shell harnesses. Their assertions are Go tests now, so they run on
  every platform instead of macOS alone — and the last interpreter executing in CI
  went with them.

## [2.0.0] - 2026-06-17

ssh-manager is **rewritten in Go** as a single self-contained binary - no interpreter
runtime to install. Behavior is unchanged: the same `manifest.json` /
`inventory.json` / `providers.json` formats, the same `~/.ssh` layout and
managed-block markers, the same `sshmgr` command surface and `SSH_MANAGER_*`
environment variables. A v1 home works as-is.

### Changed

- **Pure Go, no interpreter.** Every verb (init, import, migrate, reconcile, keygen,
  config, diff, validate, doctor, profile, host, providers, net, knownhosts,
  snapshots, bundle, restore, recover, load, deploy, rotate, rollback, list,
  view, expiry, audit, notify, tui) is native Go. The binary is a ~10 MB static
  executable with no embedded interpreter (was ~30-50 MB with a frozen interpreter).
- **More platforms.** Cross-compiles to macOS (Apple Silicon **and Intel**),
  Linux (amd64/arm64), and Windows (amd64) from a single build - Intel mac, which
  the bundled-interpreter build couldn't ship, is supported again.
- Provider key management (GitHub `gh`, GitLab `glab`, DigitalOcean / Vultr /
  Hetzner / Linode / Scaleway REST, and a config-driven generic REST), the age
  bundle/restore, the desktop notifier, and the scheduled job (launchd / systemd /
  cron / schtasks) are all reimplemented natively. Bundles and `~/.ssh` snapshots
  remain interoperable with v1.

### Notes

- The list/view/expiry views now print plain text rather than the v1 `rich`
  tables; the data shown is the same.
- The v1 implementation remains available at the `v0.1.0` tag and as the
  parity reference in `src/`. (Since removed - see Unreleased. The reference is
  now the `v1-final` tag.)

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
  package version has a single source (v1's package metadata); `--version` flag
  added.

### Quality

- Typed throughout, linted, and covered by a unit
  suite plus an end-to-end smoke (`make e2e`). Output uses **rich**, prompts use
  one toolkit per concern.
- CI runs the suite on macOS / Linux (3.11-3.13) and the platform layer on
  Windows, plus CodeQL, secret scanning (gitleaks), and pre-commit. Releases
  build and attach artifacts to a GitHub Release on a `v*` tag.

[Unreleased]: https://github.com/simtabi/ssh-manager/compare/v3.5.0...HEAD
[3.5.0]: https://github.com/simtabi/ssh-manager/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/simtabi/ssh-manager/compare/v3.2.0...v3.4.0
[3.2.0]: https://github.com/simtabi/ssh-manager/compare/v3.1.1...v3.2.0
[3.1.1]: https://github.com/simtabi/ssh-manager/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/simtabi/ssh-manager/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/simtabi/ssh-manager/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/simtabi/ssh-manager/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/simtabi/ssh-manager/releases/tag/v0.1.0
