# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately to **opensource@simtabi.com**.
Do **not** open a public issue for a security report.

Include, where possible: a description of the issue, affected version(s),
reproduction steps, and any suggested remediation. We aim to acknowledge reports
within a few business days and will keep you updated on remediation progress.

## Scope notes for this project

`ssh-manager` manages SSH private keys and config. A few invariants are
security-load-bearing - please flag any regression in these:

- **Secrets never touch git.** Private keys live in `~/.ssh`; the per-user home
  (the OS-standard config dir, e.g. `~/.config/ssh-manager`) holds `.env`,
  `age-identity.txt`, `*.age` bundles, `log/audit.log`, and `snapshots/`. Both live
  outside any repository; in the project checkout the equivalent paths are also
  gitignored, and a `gitleaks` / `detect-private-key` pre-commit hook (plus a
  gitleaks CI job) is the safety net.
- **Key passphrases.** When you generate passphrase-protected keys, the
  passphrase is passed to `ssh-keygen` on its command line (it has no stdin
  channel for generation), so it is briefly visible to other local users via
  `ps`/`/proc`. Avoid passphrase generation on shared multi-user hosts.
- **Provider tokens at rest.** A provider `token_env` (e.g. `GH_TOKEN`) in the
  home `.env` is plaintext at mode `0600`. To keep it out of plaintext, set the
  value to `cmd:<command>` and the token is fetched at use-time from any secret
  manager (it never touches disk):
  `GH_TOKEN=cmd:op read op://Private/GitHub/token`, or
  `cmd:keyring get ssh-manager gh_token`, or `cmd:age -d -i <id> token.age`.
- **Permissions are enforced.** Directories `700`, private keys + `config` `600`,
  `.pub` + `known_hosts` `644` - set on create and re-asserted by `doctor`.
- **Per-profile isolation.** Everything for an identity lives under
  `~/.ssh/profiles/<profile>/` - keys, config, and its **own** `known_hosts`. With
  `IdentitiesOnly yes` + per-profile `UserKnownHostsFile`, neither a key nor a
  trusted host key ever bleeds across identities (even on a shared host).
- **The encrypted bundle never contains `.env`** (it holds the age recipient
  refs that unlock the bundle).

## Supported versions

This project is pre-1.0; security fixes land on `main` and the latest release.
