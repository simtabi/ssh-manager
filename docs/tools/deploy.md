# deploy - install a public key on its target(s)

```sh
sshmgr deploy <key> [target]
```

- `<key>` is a key name (e.g. `work_unc-ed25519`). The key must already be minted
  (`sshmgr reconcile` or `sshmgr keygen`).
- `[target]` is an optional host alias. Omitted → deploy to **every** host that
  uses the key (one for `per_service`, all for a `shared` profile key).

Deploy installs the key's **public** half and records the deployment in
`inventory.json` (keyed by fingerprint) + the audit log. It's idempotent - one
entry per target.

## Providers (Strategy, pluggable)

A host names a provider (`"provider": "github"`); none → generic SSH. Resolution
order:

1. **Named adapter** (richer: API/CLI add + list + revoke + auto-record)
2. **Generic SSH** → `ssh-copy-id` to any reachable server
3. **Web-panel / manual** → open the keys page, paste, record a manual deployment

| Provider | category | deploy | needs |
|---|---|---|---|
| `generic-ssh` (default) | server | `ssh-copy-id -i <pub> [-p port] user@host` | reachable host |
| `github` | vcs | `gh ssh-key add` | `gh` + a token (`token_env`, default `GH_TOKEN`) |
| `gitlab` | vcs | `glab ssh-key add` | `glab` + `GLAB_TOKEN` |
| `ploi` / unknown | panel/generic | manual (prints the panel URL) | - |

When a VCS provider has no token/CLI it **degrades to the manual path** - the
deployment is recorded as `needs-redeploy` (unverified) and you finish it in the
web UI. Two accounts on one provider stay separate via per-host `token_env`
(`GH_TOKEN` vs `GH_TOKEN_SIMTABI`).

## Verified vs needs-redeploy

A deployment is `verified` when the tool confirmed it (ssh-copy-id / API success);
manual steps are `unverified` until `audit` compares the key against the
server's `authorized_keys` / the account's key list.

## Examples

```sh
sshmgr deploy work_unc-ed25519            # ssh-copy-id to sc.its.unc.edu:443
sshmgr deploy personal_github-ed25519     # gh ssh-key add (or manual if no token)
sshmgr deploy shareddemo_all-ed25519      # fans out to every host in the profile
sshmgr audit                              # see what's deployed where
```
