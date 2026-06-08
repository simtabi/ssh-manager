# providers - deploy to any VCS / service (cloud, enterprise, self-hosted)

Providers are **config-driven** (`~/.config/ssh-manager/providers.json`) and pluggable. A host
names a provider; the provider's `kind` selects the adapter and its
`host` points it at a specific instance - so the *same* adapter serves
`github.com` and GitHub Enterprise, `gitlab.com` and a self-hosted GitLab, etc.

## How a public key gets deployed

For a **public** key the universal path is "open the keys page, paste, record" -
which works for *every* VCS. CLI/API automation is a convenience on top:

1. **Named adapter with a CLI + token** → automated add/list/remove
   (GitHub via `gh`, GitLab via `glab`; cloud *and* enterprise/self-hosted are
   selected by the instance `host`, passed to the CLI via its environment -
   `GH_HOST`/`GH_ENTERPRISE_TOKEN` for gh, `GITLAB_HOST`/`GITLAB_TOKEN` for glab).
2. **Generic SSH** → `ssh-copy-id` to any reachable server.
3. **Web-panel / manual** → the tool opens the correct per-instance keys URL,
   you paste, it records the deployment. This is the universal fallback.

## The provider catalog (shipped default; your file is optional)

The full catalog below ships **with the package** and is used as-is - you don't
need a `providers.json` for it to work. To customize, materialize an editable copy
into your home and edit it:

```sh
sshmgr providers --export      # writes <home>/providers.json (the shipped catalog)
sshmgr providers               # shows the active catalog + which credentials are set
```

Resolution: `<home>/providers.json` if you created one, else the shipped default
(kept byte-identical to the repo's `config/providers.json`). `sshmgr doctor` prints
which source is active. Delete your file to track the shipped default again.

| Provider name | kind | category | automated? | notes |
|---|---|---|---|---|
| `github` | github | vcs | ✅ `gh` | github.com |
| `github-enterprise` | github | vcs | ✅ `gh` (`GH_HOST`) | set `host` + `GHE_TOKEN` |
| `gitlab` | gitlab | vcs | ✅ `glab` | gitlab.com |
| `gitlab-self-hosted` | gitlab | vcs | ✅ `glab` (`GITLAB_HOST`) | set `host` + `GLAB_TOKEN` |
| `bitbucket` | bitbucket | vcs | web-panel | bitbucket.org |
| `bitbucket-server` | bitbucket-server | vcs | web-panel | Data Center / Server |
| `gitea` / `gitea-self-hosted` | gitea | vcs | web-panel | |
| `codeberg` | codeberg | vcs | web-panel | |
| `forgejo` | forgejo | vcs | web-panel | self-hosted |
| `gogs` | gogs | vcs | web-panel | self-hosted |
| `sourcehut` | sourcehut | vcs | web-panel | meta.sr.ht |
| `azure-devops` | azure-devops | vcs | web-panel | |
| `aws-codecommit` | aws-codecommit | vcs | web-panel | IAM SSH key |
| `digitalocean` | digitalocean | **vps** | ✅ REST API | `DIGITALOCEAN_TOKEN` (account keys) |
| `vultr` | vultr | **vps** | ✅ REST API | `VULTR_API_KEY` |
| `hetzner` | hetzner | **vps** | ✅ REST API | `HCLOUD_TOKEN` |
| `linode` | linode | **vps** | ✅ REST API | `LINODE_TOKEN` |
| `scaleway` | scaleway | **vps** | ✅ REST API | `SCW_SECRET_KEY` + `SCW_PROJECT_ID` |
| _your own_ | **rest** | **vps** | ✅ REST API | config-driven - define any REST provider in `providers.json` |
| `ploi` / `forge` / `cpanel` | web-panel | panel | web-panel | hosting panels |
| `generic-ssh` | ssh | server | ✅ `ssh-copy-id` | any reachable server |
| `manual` | web-panel | generic | manual | anything else |

The **vps** adapters manage *account* keys (the ones in your provider dashboard,
used when creating servers) via REST; for keys on a *running* server use
`generic-ssh` (`authorized_keys`). See **[vps.md](vps.md)** for the full
DigitalOcean / Vultr / Hetzner / Linode / GCP / AWS workflow.

`list --type vcs` queries by **category**, so it spans every provider above.

## Add your own instance (enterprise / self-hosted / any service)

Copy a template entry, set `host` + (optionally) `token_env`, and reference its
name from a host:

```json
// ~/.config/ssh-manager/providers.json
"gitlab-acme": {"category": "vcs", "kind": "gitlab", "host": "gitlab.acme.io",
                "cli": "glab", "token_env": "GLAB_ACME_TOKEN"}
```

```json
// ~/.config/ssh-manager/manifest.json - a host using it
{"alias": "acme", "hostname": "gitlab.acme.io", "user": "git",
 "provider": "gitlab-acme", "token_env": "GLAB_ACME_TOKEN",
 "key_name": "work_acme-ed25519"}
```

Then `sshmgr deploy work_acme-ed25519`. With `glab` + the token it adds the key
to your self-hosted GitLab; without them it opens
`https://gitlab.acme.io/-/user_settings/ssh_keys` for you to paste.

A brand-new service the tool has never heard of? Add an entry with
`"kind": "web-panel"` and a `"keys_url"`, or just use `provider: "manual"`.
Nothing is hardcoded - *any* VCS or service works.

## Add a REST provider with no code (`kind: rest`)

Any cloud with a simple key API (one auth header, a list field, create/delete by
id) can be added purely in config - no adapter class:

```json
// ~/.config/ssh-manager/providers.json
"acme-cloud": {"category": "vps", "kind": "rest", "token_env": "ACME_TOKEN",
  "rest": {"base_url": "https://api.acme.com/v1", "list_path": "/ssh_keys",
           "list_field": "ssh_keys", "id_field": "id", "name_field": "name",
           "public_key_field": "public_key", "create_path": "/ssh_keys",
           "delete_path": "/ssh_keys/{id}",
           "auth_header_name": "Authorization", "auth_header_prefix": "Bearer "}}
```

`deploy`/`verify`/`rotate`/delete then work against that API like any built-in
VPS provider. For an API with a non-Bearer header (e.g. Scaleway's
`X-Auth-Token`), set `auth_header_name`/`auth_header_prefix` accordingly. Add a
`rename_path` (+ optional `rename_method`/`rename_field`) to support relabeling.

If the API paginates, set `next_field` to the dotted path of the next-page URL in
the response (e.g. `"next_field": "links.next"`); ssh-manager then follows it. Without
`next_field` the list is assumed to be a single page - set a large page size in
`list_path` if your API needs one, or the listing may be truncated.
