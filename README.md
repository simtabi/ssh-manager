# ssh-manager

Profile-based **SSH key & config lifecycle manager**. The manifest is the single
source of truth; `~/.ssh` is generated, reproducible output rebuilt by
`reconcile`. Profiles model **identity** (work · personal · simtabi · development
· school), not technology.

macOS, **Linux**, and **Windows** are all first-class - each validated end-to-end
on its own CI runner (Linux: systemd-user/cron + `notify-send`; Windows: `icacls`
owner-only ACLs, `schtasks`, PowerShell toast, plus a real reconcile/perms e2e).

## Install

```sh
pip install ssh-manager      # or: pipx install ssh-manager
sshmgr doctor           # verify deps, perms, agent, known_hosts, drift
```

Or from a clone (this is also the dev setup):

```sh
git clone https://github.com/simtabi/ssh-manager && cd ssh-manager
.build/bootstrap.sh     # .venv + editable install + pre-commit hooks
. .venv/bin/activate
```

Full steps in [docs/installation.md](docs/installation.md).

## Quick start

```sh
sshmgr init                  # create/converge ~/.config/ssh-manager (--force resets seeds, backing up first)
# init seeds an EMPTY manifest - add profiles/hosts before reconcile mints anything:
#   edit ~/.config/ssh-manager/manifest.json, or: sshmgr profile add / host add, or: sshmgr import
sshmgr reconcile --dry-run   # preview what would change
sshmgr reconcile             # build ~/.ssh from the manifest (mints missing keys)
sshmgr keygen work           # mint a profile's keys; warns + skips any that already exist
sshmgr keygen work --force   # overwrite existing keys (prompts; ~/.ssh snapshotted first)
sshmgr config check          # confirm config matches manifest (exit≠0 on drift)
sshmgr config show github-simtabi   # ssh -G for one alias
sshmgr import ~/.ssh/config   # onboard an existing setup into the manifest
sshmgr diff                  # manifest vs. on-disk reality

# reconcile auto-pins reachable hosts' known_hosts; for a VPN-gated host, connect
# the VPN then pin it (fingerprint-verified). doctor flags any host still unpinned.
sshmgr knownhosts pin --all        # review fingerprints + pin (needed for VPN-gated hosts)
sshmgr deploy work_unc-ed25519     # install the pubkey on its target (ssh-copy-id/gh/REST/manual)
sshmgr validate                    # check every keypair: parses, pub matches priv, perms ok
sshmgr providers                   # configured providers + which have credentials set
sshmgr list --type vcs             # filterable tree across profiles
sshmgr audit                       # where each key is deployed + expiry (+ recent activity)
sshmgr expiry                      # per-key rotation-age table
sshmgr rotate work_unc-ed25519     # zero-downtime staged rotation (single-old archive)
sshmgr notify install              # scheduled desktop reminders before keys are due
sshmgr bundle -o ~/Backups         # age-encrypted backup (keys + state; never .env)
sshmgr restore ~/Backups/ssh-manager-*.age   # true recovery of the same keys on a new machine
sshmgr snapshots restore           # one-command undo of ~/.ssh from a local backup
sshmgr recover work_unc-ed25519    # break-glass: snippet to paste into a locked-out console
sshmgr tui                         # interactive arrow-key UI over everything above
```

Most destructive verbs take `--yes`/`-y` to run non-interactively (and the
deletes take `--revoke`).

## Command surface

| Verb | Purpose |
|---|---|
| `init [--force] [--backup]` | create/converge `~/.config/ssh-manager` (dirs+perms+seeds); `--force` resets seeds, `--backup` keeps the old ones |
| `migrate [--force]` | move a legacy `~/.sshmgr` to the standard home (`--force` if both exist) |
| `doctor [--fix] [--json]` | deps, perms, agent, known_hosts, ≤1-old, drift (`--fix` repairs perms; `--json` for scripting) |
| `reconcile [--dry-run] [--no-pin]` | manifest → `~/.ssh`: build tree, mint missing keys, render, perms, auto-pin reachable hosts (`--no-pin` / `SSH_MANAGER_AUTO_PIN=0` to skip) |
| `keygen <profile\|host> [--force] [--no-pin]` | targeted generation; warns + skips existing keys, `--force` overwrites (prompts; ~/.ssh snapshotted first) |
| `config check` | verify config matches manifest (read-only; exit≠0 on drift) |
| `config render [--dry-run]` | re-render config files from the manifest |
| `config show [alias]` | print resolved config (or `ssh -G` for one alias) |
| `import [path]` | onboard an existing `~/.ssh` (adopts keys) into manifest + inventory |
| `diff` | preview manifest vs. on-disk reality |
| `list [--profile/--provider/--type/--tag]` | filterable tree across profiles |
| `view <profile\|alias>` | resolved host config + key + deployment status |
| `validate [key\|profile]` | check keypairs: parse, pub matches priv, perms (exit≠0 on fail) |
| `providers [--export [--force]]` | list the active catalog + credential state; `--export` writes an editable `<home>/providers.json` |
| `net [selector]` | connection status per host + VPN indicator; warns on `requires_vpn` hosts |
| `deploy <key> [target]` | install pubkey via provider (ssh-copy-id / gh / glab / REST / manual) + record |
| `load <profile>` | add a profile's keys to the agent (keychain on macOS) |
| `audit [--notify]` | deployment/expiry/hygiene + recent activity (+ desktop alert) |
| `expiry` | per-key rotation-age table (ok/due_soon/overdue) |
| `rotate <key> [--allow-unverified]` | zero-downtime staged rotation (single-old archive) |
| `rollback <key>` | restore the single `/old/` predecessor |
| `bundle [-r recipient] [-o dir]` | age-encrypted backup (keys + state; no `.env`) |
| `restore <bundle> [-i identity]` | decrypt + lay the same keys back (true recovery) |
| `snapshots list\|restore\|prune` | local reversible `~/.ssh` backups |
| `recover [key]` | break-glass console snippet (per key) / interactive fixkeys tool |
| `notify install\|test` | scheduled launchd/cron/systemd expiry notifier |
| `profile add\|edit\|delete` | manage a profile (delete revokes + prunes) |
| `host add\|edit\|delete` | manage a host within a profile |
| `knownhosts init [PROFILE] [--all] [--user] [--force]` | initialize known_hosts (create file + pin reachable hosts): a profile, `--all` profiles, and/or `--user` (`~/.ssh/known_hosts`) |
| `knownhosts pin [HOST] [--all]` | seed per-profile known_hosts via ssh-keyscan (confirmation) |
| `tui` | interactive arrow-key UI over the Facade |
| `version` | print the version |

Cross-cutting flags: `--passphrase`/`--no-passphrase` (protect new keys, default
off); `--yes`/`-y` on destructive verbs (`rotate`, `rollback`, `restore`,
`snapshots restore`, `profile/host delete`, `knownhosts pin`, `keygen --force`),
with `--revoke` for the deletes.

Output uses **rich** (tables/trees/panels + status icons), prompts use
**questionary**, and the CLI is **typer** - one toolkit per concern, no
reinvented formatting.

## Providers - all VCS + cloud VPS

Providers are config-driven (`~/.config/ssh-manager/providers.json`) and pluggable. The same
adapter serves `github.com` and GitHub Enterprise, `gitlab.com` and self-hosted
GitLab, plus Bitbucket / Gitea / Codeberg / Forgejo / Gogs / SourceHut / Azure
DevOps / AWS CodeCommit. **Cloud VPS account keys** - DigitalOcean · Vultr ·
Hetzner · Linode · Scaleway, or **any** REST API via `kind: rest` (no code) -
deploy/rotate/validate the same way. See
[docs/tools/providers.md](docs/tools/providers.md) and
[docs/tools/vps.md](docs/tools/vps.md).

## Safety: clean state + backups

Every mutating command passes through one guard that **(1)** takes the advisory
lock, **(2)** sweeps stale `.*.tmp` crash residue, and **(3)** snapshots `~/.ssh`
to `~/.config/ssh-manager/snapshots/ssh-<ts>.tar.gz` (perms 600, last 10 kept) before changing
anything - including a `keygen --force` overwrite. Combined with atomic writes,
`~/.ssh` is always left internally consistent, and any run is reversible with
`sshmgr snapshots restore`. The age `bundle` is the separate *off-machine*
disaster-recovery path; snapshots are local short-term undo; `recover` is the
break-glass escape hatch when you're locked out entirely.

## Documentation

- **[Feature catalog](docs/features.md)** - every command, what it does, and how it's tested
- [Installation](docs/installation.md) · [Configuration](docs/configuration.md) (manifest, profiles, hosts, `.env`) · [Architecture](docs/architecture.md) (layers, patterns, the one-renderer rule)
- Tools: [deploy](docs/tools/deploy.md) · [providers](docs/tools/providers.md) · [vps](docs/tools/vps.md) · [rotate](docs/tools/rotate.md) · [expiry](docs/tools/expiry.md) · [bundle](docs/tools/bundle.md) · [validate](docs/tools/validate.md) · [recover](docs/tools/recover.md) · [knownhosts](docs/tools/knownhosts.md) · [network](docs/tools/network.md) · [tui](docs/tools/tui.md)
- [Release](docs/release.md)

## Layout

- `src/ssh_manager/` - Python package (`core` · `services` · `providers` · `platforms` · `util` · `data/fixkeys.sh`)
- **Per-user home** - OS-standard config dir + `ssh-manager` folder (`~/.config/ssh-manager` on Linux/macOS, `%APPDATA%\ssh-manager` on Windows; `$SSH_MANAGER_HOME` overrides). Holds manifest.json, inventory.json, `.env` (0600), `log/`, `snapshots/`, `.state/`, and an optional providers.json. Created by `sshmgr init`; full layout + resolution in [docs/installation.md](docs/installation.md).
- `config/` - the repo's source-of-truth defaults (example manifest/inventory + the providers catalog + schema/). `providers.json` here is packaged and used as the shipped default when the user has none; the rest is example/dev seed, never auto-loaded.
- `docs/` - installation, configuration, architecture, tools/, release
- `Makefile` - dev front door at the repo root (`make doctor|test|lint|e2e|...`)
- `.build/` - dev tooling the Makefile dispatches to: `bootstrap.sh` (installer),
  `e2e.sh` (end-to-end smoke), `feature-check.sh`, `sync-data.sh`

## Status

The full CLI + TUI feature set is complete: the OS-aware platform layer, the
single config renderer, `reconcile`/`config`/`import`/`diff`/`init`/`doctor`,
`list`/`view`/`validate`/`providers`, pluggable **deploy** (ssh-copy-id / gh /
glab / cloud-VPS REST / web-panel-manual) with inventory tracking, **rotation** +
`rollback` + **expiry**/notifier, **bundle/restore** (age; true same-key
recovery), break-glass **recover**, the interactive **tui**, profile/host CRUD,
`known_hosts` pinning, and a rich presentation layer - all idempotent, atomic,
and `mypy --strict` / `ruff` / `pytest` green, with an end-to-end smoke
(`make e2e`).

macOS, Linux, and Windows are all first-class - each validated end-to-end on its
own CI runner. Next: a desktop app.

## License

MIT © Simtabi LLC - see [LICENSE](LICENSE).
