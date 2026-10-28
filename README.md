# simtabi/ssh-manager

<!-- Three badges, not the usual four: sshmgr ships as a static binary and has no
     package-registry release, so a registry-version badge would have no target. -->
[![Tests](https://img.shields.io/github/actions/workflow/status/simtabi/ssh-manager/ci.yml?branch=main&label=tests)](https://github.com/simtabi/ssh-manager/actions/workflows/ci.yml)
[![Static analysis](https://img.shields.io/github/actions/workflow/status/simtabi/ssh-manager/codeql.yml?branch=main&label=codeql)](https://github.com/simtabi/ssh-manager/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Profile-based SSH key and config lifecycle manager: one manifest is the source
> of truth, and `~/.ssh` is reproducible output.

A single static binary (`sshmgr`) with no runtime dependencies. macOS, Linux and
Windows are all first-class; OpenSSH is the only requirement.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/simtabi/ssh-manager/main/src/scripts/install.sh | bash
sshmgr doctor
```

Windows: `irm https://raw.githubusercontent.com/simtabi/ssh-manager/main/src/scripts/install.ps1 | iex`. Also
`go install github.com/simtabi/ssh-manager/src/v3/cmd/sshmgr@latest`, or a binary from
[Releases](https://github.com/simtabi/ssh-manager/releases). Every path, and where
per-user state lives, is in [docs/installation.md](docs/installation.md).

## Quick start guide and usage

### Getting started

`init` seeds an **empty** manifest; add a profile and a host before `reconcile`
mints anything:

```sh
sshmgr init                  # create ~/.config/ssh-manager (dirs, perms, seed files)
sshmgr profile add work
sshmgr host add work gh -H github.com -u git      # or edit manifest.json directly
sshmgr host apply work web1 203.0.113.10 deploy web   # add-or-update from a compact spec
sshmgr import ~/.ssh/config                        # or onboard an existing setup
```

### Usage

Build `~/.ssh` from the manifest:

```sh
sshmgr reconcile --dry-run   # preview: what would be minted, what would be written
sshmgr reconcile             # build ~/.ssh from the manifest
sshmgr config check          # confirm the file matches the manifest (exit != 0 on drift)
```

Get a key onto its target:

```sh
sshmgr deploy work_gh-ed25519    # ssh-copy-id, gh, glab, a REST API, or manual
sshmgr validate                  # every keypair parses and the halves match
```

The full walkthrough is in [Getting started](docs/getting-started.md); everything
else is in the [documentation index](#documentation).

## <a name="documentation"></a>Documentation

### Guides

- [Installation](docs/installation.md) — install paths, requirements, and where per-user state lives.
- [Getting started](docs/getting-started.md) — first run, from `init` to a deployed key.
- [Configuration](docs/configuration.md) — the manifest, profiles, hosts, `.env`, environment variables.
- [Architecture](docs/architecture.md) — packages, key flows, and why the v2 layout is what it is.
- [Release](docs/release.md) — the tag-driven GoReleaser flow.

### Reference

- [Feature catalog](docs/features.md) — every command, what it does, and how it is tested.
- [`doctor`](docs/tools/doctor.md) — what it checks, `--fix`, `--json`, `--strict`.
- [`deploy`](docs/tools/deploy.md) — installing a public key on its target.
- [`providers`](docs/tools/providers.md) — the adapter catalog and how to extend it.
- [VPS keys](docs/tools/vps.md) — cloud account keys and server keys.
- [`rotate`](docs/tools/rotate.md) — zero-downtime staged rotation and rollback.
- [`expiry`](docs/tools/expiry.md) — rotation age and scheduled reminders.
- [`knownhosts`](docs/tools/knownhosts.md) — pinning host keys into the trust store.
- [`git`](docs/tools/git.md) — checkouts' GitHub remotes in profile SSH, plain SSH or HTTPS mode.
- [`vm`](docs/tools/vm.md) — local VMs as hosts, addressed through their hypervisor.
- [`export`](docs/tools/export.md) — a flat `ssh_config` or a Termius CSV, for tools that cannot read the split config.
- [`net`](docs/tools/network.md) — reachability and VPN-gated hosts.
- [`validate`](docs/tools/validate.md) — keypair integrity checks.
- [`bundle`](docs/tools/bundle.md) — encrypted backup and restore.
- [`history`](docs/tools/history.md) — every change sshmgr has made, filtered by host, profile or key.
- [`serve`](docs/tools/serve.md) — the web UI: overview, hosts, keys, snapshots and history in a browser, with previewed changes.
- [`recover`](docs/tools/recover.md) — break-glass when you are locked out.
- [`tui`](docs/tools/tui.md) — the interactive menu.

### Recipes

- [Add or update many hosts at once](docs/recipes/host-specs.md) — `host apply` with `<alias> <host> <user> [role]` lines, re-runnable.
- [Two GitHub accounts on one machine](docs/recipes/two-github-accounts.md) — one hostname, two identities, neither able to act as the other.
- [Keep keys in 1Password](docs/recipes/keep-keys-in-1password.md) — private keys generated and rotated inside a vault; only the `.pub` on disk.
- [Use a GitHub machine user](docs/recipes/github-machine-user.md) — one bot key with read access to every org repo, rotated in one command.
- [Group profiles into categories](docs/recipes/group-profiles-into-categories.md) — `internal`, `clients`, `others`: one directory and one `config` file each.
- [Switch checkouts to profile SSH](docs/recipes/switch-git-remote-modes.md) — each owner's own key, every URL proven before it is written.
- [Use a local VM as a devbox](docs/recipes/devbox-vm.md) — reach a VM by name whatever its IP, and point Docker at it.
- [Import your hosts into Termius](docs/recipes/import-hosts-into-termius.md) — every host with its user, then `termius keys` to paste each key into Termius's Keychain (the CSV carries no keys).
- [Reach a server through Cloudflare Access](docs/recipes/cloudflare-access.md) — `ssh <alias>` through `cloudflared`, with no SSH port open to the internet.
- [Onboard an existing `~/.ssh`](docs/recipes/onboard-an-existing-ssh-dir.md) — bring a hand-built setup under management without regenerating anything.
- [Rotate a key with no downtime](docs/recipes/rotate-a-key.md) — stage, verify, commit; and how to step back.
- [Rotate or repair many keys at once](docs/recipes/rotate-many-keys.md) — a category or everything in one batch, and rebuilding `.pub` files.
- [Work against a sandbox](docs/recipes/dev-mode.md) — exercise every verb without touching your real `~/.ssh`.
- [Back up, and restore onto a new machine](docs/recipes/back-up-and-restore.md) — the only path that recovers the same keys.
- [Recover from a locked-out server](docs/recipes/recover-from-lockout.md) — break-glass with no working SSH.
- [Run it in CI](docs/recipes/run-in-ci.md) — non-interactive, sandboxed, failing loudly.

## Community

[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## License

MIT © Simtabi LLC — see [LICENSE](LICENSE).
