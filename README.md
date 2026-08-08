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
- [`net`](docs/tools/network.md) — reachability and VPN-gated hosts.
- [`validate`](docs/tools/validate.md) — keypair integrity checks.
- [`bundle`](docs/tools/bundle.md) — encrypted backup and restore.
- [`recover`](docs/tools/recover.md) — break-glass when you are locked out.
- [`tui`](docs/tools/tui.md) — the interactive menu.

### Recipes

- [Two GitHub accounts on one machine](docs/recipes/two-github-accounts.md) — one hostname, two identities, neither able to act as the other.
- [Onboard an existing `~/.ssh`](docs/recipes/onboard-an-existing-ssh-dir.md) — bring a hand-built setup under management without regenerating anything.
- [Rotate a key with no downtime](docs/recipes/rotate-a-key.md) — stage, verify, commit; and how to step back.
- [Work against a sandbox](docs/recipes/dev-mode.md) — exercise every verb without touching your real `~/.ssh`.
- [Back up, and restore onto a new machine](docs/recipes/back-up-and-restore.md) — the only path that recovers the same keys.
- [Recover from a locked-out server](docs/recipes/recover-from-lockout.md) — break-glass with no working SSH.
- [Run it in CI](docs/recipes/run-in-ci.md) — non-interactive, sandboxed, failing loudly.

## Community

[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md)

## License

MIT © Simtabi LLC — see [LICENSE](LICENSE).
