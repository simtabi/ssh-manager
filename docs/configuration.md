# Configuration

Everything lives in the **manifest** (`~/.config/ssh-manager/manifest.json`) - the single
source of truth. You never hand-edit ssh-manager's part of `~/.ssh/config`; you edit the
manifest (or use the `host`/`profile` verbs) and re-render. A JSON Schema for the
manifest and inventory lives in `src/config/schema/` (and matches the Go models in `src/internal/core`,
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

Match all
Include ~/.ssh/profiles/internal/config   # only when a profile has a category
...
Host github-imani                          # uncategorized profiles render inline
    ...
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
> VPS or a university host, `user` *is* the real account, e.g. `ploi`, `researcher`.)

## Manifest reference

```jsonc
{
  "version": 1,
  "defaults": { /* see below */ },
  "profiles": {
    "work": {
      "category": "others",               // optional: profiles/others/work/ + profiles/others/config
      "key_store": "file",                // or "1password" (then op_vault is required)
      "op_vault": null,                   // the 1Password vault holding this profile's keys
      "key_scope": "per_service",         // or "shared"
      "key_name": null,                    // set only when key_scope == "shared"
      "hosts": [
        {
          "alias": "hpc",                  // the ssh Host alias you type
          "hostname": "hpc.example.edu",    // real host
          "user": "researcher",
          "port": 443,                      // default 22
          "provider": "generic-ssh",       // adapter name from providers.json (optional)
          "token_env": "GH_TOKEN_WORK",    // env var holding this host's provider token (optional)
          "key_name": "work_hpc-ed25519",  // omit on shared-scope profiles
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
| `onepassword_agent` | platform default | the 1Password SSH agent socket for `key_store: 1password` profiles (see [Key stores](#key-stores)) |
| `git.mode` | `profile` | default GitHub remote mode for `sshmgr git use`: `profile`, `ssh` or `https` |
| `git.profile` | unset | the default identity: its GitHub key is bound to a rendered `Host github.com` (ssh mode), and it is used for owners `git.orgs` does not list. Unset, no `Host github.com` is rendered |
| `git.orgs` | `{}` | GitHub owner → profile, for `sshmgr git` (see [tools/git.md](tools/git.md)) |

All three `git` fields are optional and the key is omitted when unset, so a manifest without them renders
and saves exactly as before. `ssh` mode needs `git.profile`, and no host may use the alias `github.com`
while it is set.

### `vm`

A host with `vm` is a local VM. sshmgr renders `ProxyCommand "<sshmgr>" vm proxy <alias>` for it (the
only ProxyCommand that can appear in the config; `raw_options` still may not set one), and resolves the
VM's address through its hypervisor on each connection.

```jsonc
{"alias": "devbox", "hostname": "devbox", "user": "imani",
 "vm": {"hypervisor": "parallels", "name": "Ubuntu 24.04"}}
```

`hypervisor` is one of `parallels`, `vmpal`, `vmware`, `utm`, `lima` (OrbStack and Podman keep their own
SSH and are not hosts); `name` is the VM as the hypervisor lists it, spaces allowed. See
[tools/vm.md](tools/vm.md).

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
under `~/.ssh/profiles/<profile>/`** (or `profiles/<category>/<profile>/`) - its
keys, and nothing else - and nothing crosses profiles:

- Two GitHub accounts are two profiles sharing `hostname: github.com` via distinct
  aliases (`github.com` vs `github-simtabi`) and `IdentitiesOnly yes`, so each
  offers only its own key.
- Every host renders `UserKnownHostsFile ~/.ssh/known_hosts` - one hashed store,
  not one per profile. Identity isolation comes from `IdentityFile` plus a
  per-host `IdentitiesOnly yes`, not from where the trust store lives. A
  host key trusted as `personal` is **not** trusted as `simtabi` - even on the
  same `github.com` host. Pin host keys with `sshmgr knownhosts pin --all`.

## Categories

A profile may set `category` to file it one level deeper: its keys live under
`~/.ssh/profiles/<category>/<profile>/`, and its `Host` blocks render into
`~/.ssh/profiles/<category>/config`, which the root config Includes. Profiles
without one keep the flat layout and stay inline in the root config, so a
manifest that uses no categories renders exactly as before.

| Rule | Why |
|---|---|
| A category is a safe path segment | It becomes a directory name. |
| It may not share a name with an uncategorized profile | Both would own `profiles/<name>/`. |
| A categorized profile may not be named `config` or `old` | `profiles/<category>/config` is the category's file; `.../old/` is a rotation archive. |

Set it with `sshmgr profile add <name> --category <c>` or
`sshmgr profile edit <name> --category <c>`. The edit moves the key directory and
updates the inventory. See [Group profiles into categories](recipes/group-profiles-into-categories.md).

## Key stores

A profile's private keys live in one of two places, set by `key_store`:

| `key_store` | Private key | On disk | Rendered host |
|---|---|---|---|
| `file` (or omitted) | `profiles/…/<key>` | private key + `.pub` | `IdentityFile <key>` |
| `1password` | an SSH Key item titled `<key>` in `op_vault` | `.pub` only | `IdentityFile <key>.pub` + `IdentityAgent "<socket>"` |

With `1password`, `reconcile` creates the key inside 1Password with the
[`op` CLI](https://developer.1password.com/docs/cli/) and writes only its public
half. ssh then asks the 1Password agent for the key matching that `.pub`, so the
private key never touches disk. `rotate` generates replacements in the vault too.
Needs `op` (2.20 or later) signed in, and the agent turned on in the 1Password
app (Settings > Developer > Use the SSH agent); `doctor` checks both.

**The agent must serve the vault.** With no `agent.toml`, the 1Password SSH
agent offers only keys in your Personal, Private or Employee vault. Once
`~/.config/1Password/ssh/agent.toml` exists, it offers only what the file lists
(even an empty file overrides the default). For any other vault, or whenever the
file exists, list the vault as a whole:

```toml
[[ssh-keys]]
vault = "Simtabi"
```

A whole-vault entry, not one per item: a rotation's `<key>.staged` item has to be
served to be verified. `doctor` checks this for every vault a profile names.

The agent socket defaults to the platform's path (macOS
`~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`, Linux
`~/.1password/agent.sock`); set `defaults.onepassword_agent` to override it. On
Windows no `IdentityAgent` is rendered, because Microsoft OpenSSH uses one fixed
pipe for every host.

Two rules are enforced when the manifest loads:

- **Key names are unique within a vault.** The item is titled with the key name,
  so two 1Password profiles sharing a vault and a key name would share one key.
- **Keys are `ed25519`.** 1Password generates nothing else, so another
  `key_type` on a 1Password profile is rejected rather than silently ignored.

The store is per profile, not per host, so the hosts sharing a key cannot
disagree about where it lives. To move a profile into 1Password, set
`key_store` and run `sshmgr rotate` on each key: it generates the new key in the
vault and archives the old key file to `old/`. See
[Keep keys in 1Password](recipes/keep-keys-in-1password.md).

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
{"alias": "hpc", "hostname": "hpc.example.edu", "user": "researcher", "port": 443,
 "key_name": "work_hpc-ed25519",
 "raw_options": {"ProxyJump": "bastion.hpc.edu"}}
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
in `~/.config/ssh-manager/.env`, read by `internal/util/secrets`. A committed `.env-example` documents
the shape with empty values, and `sshmgr init` seeds your `.env` from it. The
`.env` is **never** committed (it's gitignored, mode 0600) and is **excluded from
the encrypted bundle**.

To avoid storing a token at rest, set its value to `cmd:<command>` - the command
runs at use-time and its trimmed stdout is the token (so it integrates with any
secret manager and the secret never touches disk):

```sh
GH_TOKEN=op://Private/GitHub/token                      # 1Password secret reference
GH_TOKEN=cmd:op read op://Private/GitHub/token          # the same, spelled out
GH_TOKEN=cmd:keyring get ssh-manager gh_token           # OS keyring
```

A value starting `op://` is read with `op read`, the whole reference as one
argument, so item and field names may contain spaces.

The command runs once per process (memoized) via the argv-only subprocess
chokepoint - no shell, no injection. A failed/empty/timed-out command yields no
token (the provider falls back to the manual paste path). Note: a literal token
that itself begins with `cmd:` would be treated as a command - real OAuth/PAT
tokens never do, but if needed, fetch such a value via `cmd:` instead.

## Dev mode

`--dev-root <dir>` (or `$SSHMGR_DEV_ROOT`) points the whole tool at a scratch
directory: `<dir>/ssh` stands in for `~/.ssh` and `<dir>/config` for the config
home. It is one root rather than two overrides, so a run cannot end up reading a
sandbox and writing your real tree. See
[Work against a sandbox](recipes/dev-mode.md).

---

[← Docs index](../README.md#documentation)
