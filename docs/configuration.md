# Configuration

Everything lives in the **manifest** (`~/.config/ssh-manager/manifest.json`) - the single
source of truth. You never hand-edit ssh-manager's part of `~/.ssh/config`; you edit the
manifest (or use the `host`/`profile` verbs) and re-render. A JSON Schema for the
manifest and inventory lives in `config/schema/` (and matches the pydantic models,
which reject unknown keys). See [installation.md](installation.md) for how the home
is resolved.

## ssh-manager owns only a marked block of `~/.ssh/config`

`reconcile` / `config render` rewrite **only** the region between

```
# Managed by ssh-manager - do not edit (run: sshmgr config render)
...
# End of ssh-manager-managed block - content outside it is preserved
```

Anything above or below that block is left untouched, so edits injected by other
tools survive a re-render. In particular, an OrbStack preamble (which must sit at
the very top of `ssh_config`, before any `Host` block) is kept at the top:

```
# Added by OrbStack: 'orb' SSH host for Linux machines
Include ~/.orbstack/ssh/config

# Managed by ssh-manager - do not edit (run: sshmgr config render)
Include profiles/*/config
Host *
    ...
# End of ssh-manager-managed block - content outside it is preserved
```

To add your own static SSH directives, put them outside the managed block (above
or below it) - they will be preserved. `~/.ssh/config` is also snapshotted before
every mutating command, so a render is always reversible via `snapshots restore`.

## Multiple identities on one host: prefix aliases to avoid collisions

When the same host serves more than one identity - the classic case is a
**personal vs. work GitHub account**, both on `github.com` - give every host a
**distinct, profile-prefixed alias** rather than using the bare hostname:

```jsonc
"personal": { "hosts": [
  { "alias": "github-personal", "hostname": "github.com", "user": "git",
    "provider": "github", "key_name": "personal_github-ed25519" } ] },
"simtabi":  { "hosts": [
  { "alias": "github-simtabi",  "hostname": "github.com", "user": "git",
    "provider": "github", "token_env": "GH_TOKEN_SIMTABI",
    "key_name": "simtabi_github-ed25519" } ] }
```

Why prefix:

- An `alias` is the `Host` block name and must be unique across the whole config.
  If one identity claims the bare `github.com`, then `git@github.com:...` *always*
  resolves to that identity - the other one can never use a `github.com` remote
  (a silent collision). Distinct prefixed aliases make each identity explicit.
- `key_name` is already profile-prefixed by ssh-manager's `<profile>_<service>-<algo>`
  convention (e.g. `personal_github-ed25519`, `simtabi_github-ed25519`), so the key
  *files* never collide. Apply the same discipline to the **alias** so the SSH
  *Host blocks* don't either.

Point each repo's remote at the right alias (the SSH user stays `git` - GitHub
requires it; it's the *alias* that selects the identity):

```sh
git remote set-url origin git@github-personal:me/my-repo.git
git remote set-url origin git@github-simtabi:simtabi/ssh-manager.git
# or, to rewrite a host globally for one account, use git's insteadOf:
git config --global url."git@github-simtabi:simtabi/".insteadOf "git@github.com:simtabi/"
```

`IdentitiesOnly yes` plus the per-profile `IdentityFile`/`UserKnownHostsFile` then
guarantees each alias offers only its own key and trusts only its own host keys.

> **The SSH `user` for GitHub/GitLab/Bitbucket must be `git`.** The account is
> identified by the **key**, not the SSH username - so a custom `user` (e.g.
> `imani_git`) breaks any plain `git@host:...` remote. Prefix the **alias** to
> separate identities; never prefix the `user`. (For real login servers like a
> VPS or a university host, `user` *is* the real account, e.g. `ploi`, `uncgit`.)

## Manifest reference

```jsonc
{
  "version": 1,
  "defaults": { /* see below */ },
  "profiles": {
    "work": {
      "key_scope": "per_service",         // or "shared"
      "key_name": null,                    // set only when key_scope == "shared"
      "hosts": [
        {
          "alias": "unc",                  // the ssh Host alias you type
          "hostname": "sc.its.unc.edu",    // real host
          "user": "uncgit",
          "port": 443,                      // default 22
          "provider": "generic-ssh",       // adapter name from providers.json (optional)
          "token_env": "GH_TOKEN_WORK",    // env var holding this host's provider token (optional)
          "key_name": "work_unc-ed25519",  // omit on shared-scope profiles
          "tags": ["app"],                  // free-form, used by `list --tag`
          "requires_vpn": false,            // true if this host is only reachable over a VPN
          "vpn_name": null,                 // which VPN (shown in the reachability hint)
          "vpn_url": null,                  // where to connect that VPN (shown in the hint)
          "raw_options": {"ProxyJump": "bastion"}   // any ssh option the schema doesn't model
        }
      ]
    }
  }
}
```

### `defaults`

| Field | Default | Meaning |
|---|---|---|
| `key_type` | `ed25519` | ssh-keygen type for new keys (`ed25519`, `ed25519-sk`, `rsa`, ...) |
| `key_scope` | `per_service` | default scope for profiles that don't set one |
| `rotate_after_days` | `365` | key lifetime → drives `expiry` (ok / due_soon / overdue) |
| `warn_before_days` | `[30,14,7,1]` | when the expiry banner starts warning |
| `expiry_check.enabled` | `true` | run the expiry check at all |
| `expiry_check.debounce_hours` | `24` | min gap between inline banners |
| `expiry_check.desktop_notify` | `true` | allow the scheduled desktop notification |
| `global_options` | `{}` | ssh options emitted under `Host *` (e.g. `AddKeysToAgent`, macOS `UseKeychain`) |

### `provider` / `token_env`

A host's `provider` names an adapter in `~/.config/ssh-manager/providers.json` (GitHub/GitLab,
the cloud-VPS REST adapters, a `kind: rest` provider, `generic-ssh`, or a
web-panel/manual entry). `token_env` overrides which env var that host's adapter
reads for its credential - so several accounts on one provider stay separate. See
[tools/providers.md](tools/providers.md) and [tools/vps.md](tools/vps.md).

Mark a host that's only reachable over a VPN with `requires_vpn: true` (and an optional `vpn_name`); `sshmgr net` and every network action then warn you to connect the VPN instead of hanging. See [tools/network.md](tools/network.md).

## Profiles model identity, not technology - everything lives under the profile

A profile is *who you're being* (work · personal · simtabi · development ·
school), not *what kind of service* a host is. **Everything for an identity lives
under `~/.ssh/profiles/<profile>/`** - its keys, rendered `config`, and its own
`known_hosts` trust store - and nothing crosses profiles:

- Two GitHub accounts are two profiles sharing `hostname: github.com` via distinct
  aliases (`github.com` vs `github-simtabi`) and `IdentitiesOnly yes`, so each
  offers only its own key.
- Each profile renders `UserKnownHostsFile ~/.ssh/profiles/<p>/known_hosts`, so a
  host key trusted as `personal` is **not** trusted as `simtabi` - even on the
  same `github.com` host. Pin host keys with `sshmgr knownhosts pin --all`.

## Key scope

- `per_service` *(default)* - one key per host: smallest blast radius.
- `shared` - one key for a whole profile (set `key_name` on the profile, omit it
  on hosts). Opt in per profile where you accept the trade-off.

## Key naming - `<profile>_<service>-<algo>`

Exactly one underscore (the profile prefix); the remainder is kebab-case. Names
are **stable** (never carry a date - that lives in the key comment + inventory).
Hardware keys end `-ed25519-sk`.

## Unmodeled ssh options - `raw_options`

For an option the schema doesn't model, add a host-level `raw_options` block
rather than hand-editing the file:

```json
{"alias": "unc", "hostname": "sc.its.unc.edu", "user": "uncgit", "port": 443,
 "key_name": "work_unc-ed25519",
 "raw_options": {"ProxyJump": "bastion.unc.edu"}}
```

Because the manifest is rendered verbatim into `~/.ssh/config` and its names become
filesystem paths, values are validated on load: names (profile/alias/key_name) may
not contain `/`, `\`, `..`, a leading `-`, whitespace, glob `*?`, or control
characters; `hostname`/`user` may not contain whitespace, newlines, or a leading
`-`; and `raw_options` (and `global_options`) reject command/code-executing keys
(`ProxyCommand`, `LocalCommand`, `PermitLocalCommand`, `RemoteCommand`, `Match`,
`Include`, `KnownHostsCommand`, `PKCS11Provider`, `SecurityKeyProvider`).
`ProxyJump` (a host, not a command) is allowed. `key_scope` must be `per_service`
or `shared`.

## `.env` (gitignored)

Secrets/refs (age recipient, per-host provider tokens) live
in `~/.config/ssh-manager/.env`, loaded via python-dotenv. A committed `.env-example` documents
the shape with empty values, and `sshmgr init` seeds your `.env` from it. The
`.env` is **never** committed (it's gitignored, mode 0600) and is **excluded from
the encrypted bundle**.

To avoid storing a token at rest, set its value to `cmd:<command>` - the command
runs at use-time and its trimmed stdout is the token (so it integrates with any
secret manager and the secret never touches disk):

```sh
GH_TOKEN=cmd:op read op://Private/GitHub/token     # 1Password CLI
GH_TOKEN=cmd:keyring get ssh-manager gh_token           # OS keyring
```

The command runs once per process (memoized) via the argv-only subprocess
chokepoint - no shell, no injection. A failed/empty/timed-out command yields no
token (the provider falls back to the manual paste path). Note: a literal token
that itself begins with `cmd:` would be treated as a command - real OAuth/PAT
tokens never do, but if needed, fetch such a value via `cmd:` instead.
