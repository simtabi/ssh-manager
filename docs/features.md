# Feature catalog

The complete, tested surface of ssh-manager. Every row is exercised by the test suite:
**U** = unit tests (`pytest`), **E** = end-to-end smoke (`make e2e`), **F** =
per-command feature check (`make feature-check`, which exercises every command in
a sandbox). Run all three with `make test e2e feature-check`.

The mental model: the **manifest** in `~/.config/ssh-manager/manifest.json` is the single source
of truth; `~/.ssh` is generated, reproducible output. Profiles model *identity*
(work · personal · simtabi · ...), not technology, and everything for an identity
lives isolated under `~/.ssh/profiles/<profile>/`.

## Home & setup

| Command | What it does | Tests |
|---|---|---|
| `init` | Create/converge the per-user home (OS-standard, e.g. `~/.config/ssh-manager`): every run (re)creates the dir structure (`log/`, `snapshots/`, `.state/`) + re-asserts perms (dirs 700, secrets 600) and seeds any **missing** starter files (manifest, inventory, `.env`) - never clobbering existing ones. `providers.json` is not seeded (the shipped catalog is used unless you create your own). | U·E·F |
| `init --force` | Overwrite the seed files with fresh defaults, **in place** (no backup). | U·F |
| `init --force --backup` | Same, but first copy the old files into `~/.config/ssh-manager/.state/init-backup-<ts>/`. | U·F |
| `migrate [--force]` | Move a legacy `~/.sshmgr` to the **resolved** home (`$SSH_MANAGER_HOME` override-aware; auto-migration handles the simple case on any command; this resolves the stranded both-exist case `doctor` warns about - `--force` backs up the current home and replaces it). | U |
| `doctor` | Verify the environment: deps, perms, agent, known_hosts, ≤1-old-key invariant, config drift, orphan/duplicate keys, alias collisions. Prints the **resolved home**, `~/.ssh`, and the active provider-catalog source; warns about a stranded legacy home. | U·E·F |
| `doctor --fix` | Re-assert canonical perms on every tool-managed path (`~/.ssh` tree + home secrets). | U·F |
| `doctor --json` | Machine-readable report for scripting/monitoring. | U |
| `version` / `--version` | Print the version. | F |

Home resolution: `$SSH_MANAGER_HOME` (alias `$SSH_MANAGER_CONFIG_DIR`) if set, else the
OS-standard config dir + `ssh-manager` folder (`~/.config/ssh-manager` on Linux/macOS,
`%APPDATA%\ssh-manager` on Windows). A legacy `~/.sshmgr` is auto-migrated. No
project-local mode. See [installation.md](installation.md) for the full layout.

## Build & verify `~/.ssh`

| Command | What it does | Tests |
|---|---|---|
| `reconcile [--no-pin]` | Make `~/.ssh` match the manifest: build the profile tree, **mint missing keys**, render config, set perms, and **auto-pin each profile's `known_hosts`** for reachable hosts (`--no-pin` or `SSH_MANAGER_AUTO_PIN=0` to skip). Snapshots `~/.ssh` first. | U·E·F |
| `reconcile --dry-run` | Preview the plan; write nothing. | E·F |
| `keygen <profile\|host> [--no-pin]` | Targeted key generation; warns + **skips** keys that already exist; auto-pins the affected profiles' `known_hosts` for reachable hosts. | U·E·F |
| `keygen ... --force [--yes]` | Overwrite existing keys (prompted; `~/.ssh` snapshotted first). | U·E·F |
| `keygen ... --passphrase/--no-passphrase` | Protect new keys with a passphrase (off by default; prompts on a TTY). | U |
| `config check` | Verify the on-disk config byte-for-byte matches a fresh render (exit ≠0 on drift). | U·E·F |
| `config render [--dry-run]` | Re-render config files from the manifest (one renderer, shared with `check`/`reconcile`). | U·E·F |
| `config show [alias]` | Print resolved config, or `ssh -G` for one alias. | U·F |
| `import [path] [--force]` | Onboard an existing `~/.ssh` (adopt keys + hosts) into the manifest + inventory. Refuses to replace a non-empty manifest without `--force` (which backs it up first). | U·F |
| `diff` | Preview manifest vs. on-disk reality (config + which keys are missing/present). | U·F |

## Inspect

| Command | What it does | Tests |
|---|---|---|
| `list [--profile/--provider/--type/--tag]` | Filterable tree across profiles. | U·E·F |
| `view <profile\|alias>` | Resolved host config + key + deployment status; shows a **VPN reminder** for `requires_vpn` hosts. | U·F |
| `validate [key\|profile]` | Check each keypair: both parse, public key is *derived from* the private (`ssh-keygen -y`), perms correct; encrypted keys are noted not failed. Exit ≠0 on failure. | U·E·F |
| `providers [--export [--force]]` | List the active provider catalog (your `<home>/providers.json` if present, else the shipped default) + whether each credential is set. `--export` writes an editable copy into the home. | U·E·F |
| `net [selector]` | Per-host connection status + a VPN/tunnel indicator. Exit ≠0 if a `requires_vpn` host is unreachable. | U·F |
| `expiry` | Per-key rotation-age table (ok / due_soon / overdue), from each key's stored `expires_on`. | U·E·F |
| `audit [--notify]` | Where each key is deployed + expiry + hygiene + recent activity (optionally fire a desktop alert). | U·E·F |

## Deploy, rotate, network/VPN

| Command | What it does | Tests |
|---|---|---|
| `deploy <key> [target]` | Install the public key on its target via the host's provider (GitHub/GitLab CLI, cloud-VPS REST, `generic-ssh` `ssh-copy-id`, or web-panel/manual) and record it. **Exits ≠0 if a target is unreachable.** | U·E·F |
| `rotate <key> [--yes] [--allow-unverified] [--passphrase]` | Zero-downtime staged rotation: stage → deploy → verify → archive (≤1 predecessor). Aborts cleanly (pulling the staged key back) if a target can't be verified or is unreachable. | U·E·F |
| `rollback <key> [--yes]` | Restore the single `/old/` predecessor (re-deploy is best-effort; skips unreachable hosts). | U·E·F |
| `load <profile>` | Add the profile's keys to the agent (Keychain on macOS). | U·F |

**Network/VPN awareness** is woven through every host-touching action. A host can be
marked `requires_vpn` (+ optional `vpn_name`, `vpn_url`). `deploy`/`rotate` run a
bounded SSH-level reachability probe first, so a down or VPN-gated host (including a
`:443` host that accepts TCP but never speaks SSH) **fails fast** with
*"connect the VPN at `<url>` and retry"* instead of hanging - and every `ssh` /
`ssh-copy-id` is hard-timeout-bounded. See [tools/network.md](tools/network.md).

## Backup & recovery

| Command | What it does | Tests |
|---|---|---|
| `bundle [-r recipient] [-o dir]` | `age`-encrypted, off-machine backup of keys + manifest + inventory + providers. **Never** includes `.env`. | U·E·F |
| `restore <bundle> [-i identity] [--yes]` | Decrypt and lay the **same** keys back (true recovery on a new machine). | U·E·F |
| `snapshots list\|restore\|prune` | Local, reversible `~/.ssh` backups (every mutating command snapshots first; last 10 kept). `restore` takes `--yes`. | U·E·F |
| `recover [key]` | Break-glass: with a key, a tailored shell snippet to paste into a locked-out console; without, the full interactive `fixkeys` tool (reads `/dev/tty`). | U·F |

## Editing, trust, scheduling, UI

| Command | What it does | Tests |
|---|---|---|
| `profile add\|edit\|delete [--yes] [--revoke]` | Manage a profile (delete can revoke deployed keys + prune). | U·F |
| `host add <profile> <alias> ...\|edit\|delete [--yes] [--revoke]` | Manage a host within a profile (alias is **positional**). | U·F |
| `knownhosts init [PROFILE] [--all] [--user] [--force]` | Initialize known_hosts (create file + pin reachable hosts, TOFU, fingerprints reported): a profile, `--all` profiles, and/or `--user` (the per-user `~/.ssh/known_hosts`). Per-store status report. | U·F |
| `knownhosts pin [HOST] [--all]` | Seed per-profile `known_hosts` via `ssh-keyscan`, showing each fingerprint and asking first. | U·F |
| `notify install\|test` | Scheduled desktop expiry reminders (launchd / systemd-user-or-cron / schtasks). | U·F |
| `tui` | Interactive arrow-key UI over the whole facade. | U |

Cross-cutting flags: `--yes`/`-y` on destructive verbs (with `--revoke` on deletes);
`--passphrase`/`--no-passphrase` on key generation.

## Providers

Config-driven (`providers.json`) and pluggable: GitHub & GitLab (CLI + token, cloud
and enterprise/self-hosted); Bitbucket, Gitea, Codeberg, Forgejo, Gogs, SourceHut,
Azure DevOps, AWS CodeCommit (web-panel); cloud-VPS account keys for DigitalOcean,
Vultr, Hetzner, Linode, Scaleway (REST); `generic-ssh`; and **any** REST key API with
no code via `kind: rest`. Details in [tools/providers.md](tools/providers.md) and
[tools/vps.md](tools/vps.md).

## Safety guarantees (always on)

- **One renderer** drives `render`/`check`/`reconcile`; `check` compares byte-for-byte.
- **Atomic + locked** state writes (temp + `os.replace` under an advisory lock).
- **Load-bearing perms** (dirs 700, private keys + config 600, public + known_hosts 644),
  set on create and re-asserted by `doctor`/`reconcile`; secrets are owner-only the
  moment they appear.
- **Snapshot before mutate** - every mutating command backs up `~/.ssh` first.
- The `.env` is gitignored, 0600, and excluded from the encrypted bundle.
