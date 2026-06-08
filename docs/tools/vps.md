# Managing SSH keys on VPS / cloud providers

There are **two independent layers** of SSH keys on a cloud host, and ssh-manager
handles both:

| Layer | What it is | ssh-manager provider |
|---|---|---|
| **Account keys** | Keys in your provider *dashboard*, offered when you **create** a server | `digitalocean` · `vultr` · `hetzner` · `linode` · `scaleway` (REST API) |
| **Server keys** | `~/.ssh/authorized_keys` on a **running** server | `generic-ssh` (ssh-copy-id / authorized_keys) |

They don't affect each other: deleting an account key never touches a live
server, and editing a server's `authorized_keys` never touches the dashboard.

> **Provenance.** This functionality was consolidated from a standalone VPS
> key-management tool. Every capability of that tool now lives in ssh-manager - see
> the [parity table](#appendix-vps-tool-parity) at the end.

---

## 1. Account keys - DigitalOcean, Vultr, Hetzner, Linode (built-in)

These manage the keys in the dashboard via each provider's REST API. Set the
token, point a host at the provider, and `deploy`/`rotate`/`delete` like any
other provider.

### Get a token

| Provider | Env var | Where |
|---|---|---|
| DigitalOcean | `DIGITALOCEAN_TOKEN` | Apps & API → Tokens (read+write) |
| Vultr | `VULTR_API_KEY` | Account → API → Personal Access Token |
| Hetzner Cloud | `HCLOUD_TOKEN` | Project → Security → API Tokens (read+write) |
| Linode | `LINODE_TOKEN` | Profile → API Tokens (SSH Keys read/write) |
| Scaleway | `SCW_SECRET_KEY` + `SCW_PROJECT_ID` | Console → Credentials (keys are project-scoped) |

Put it in `.env` (gitignored) - or use a **per-host** `token_env` if you
have several accounts on one provider.

> **Anything else with a REST key API** can be added with **no code** via
> `kind: rest` in `~/.config/ssh-manager/providers.json` - see
> [providers.md](providers.md#add-a-rest-provider-with-no-code-kind-rest).

### Add / update / remove

```sh
# a host that represents your provider account (or a specific droplet)
sshmgr host add work do-account --hostname cloud.digitalocean.com \
    --user root --provider digitalocean
sshmgr reconcile                       # mints work_do-account-ed25519 + shows its config

sshmgr deploy work_do-account-ed25519  # ADD: POST the public key to the DO account
sshmgr view do-account                 # see it recorded as deployed
sshmgr rotate work_do-account-ed25519  # ROTATE: add new -> verify via API -> remove old
sshmgr host delete work do-account     # REMOVE: prompts to revoke (DELETE the key) + prune
```

Without a token the provider **degrades to the dashboard URL** (it prints where
to paste the key), so it still works unattended-less. Keys are matched by their
base64 body, so a rename in the dashboard doesn't confuse rotation/removal.

`deploy` is **idempotent**: if the key is already in the account (matched by
body) it isn't duplicated - and if its dashboard title drifted, ssh-manager **renames**
it back to the canonical `ssh-manager <file>` rather than erroring.

### Adding another provider account (per-host token)

```json
// ~/.config/ssh-manager/manifest.json - two DigitalOcean accounts, separate tokens
{"alias": "do-personal", "hostname": "cloud.digitalocean.com", "user": "root",
 "provider": "digitalocean", "token_env": "DO_TOKEN_PERSONAL"}
```

---

## 2. Server keys - any running server (incl. GCP, AWS, bare metal)

For a **live** server, the key lives in its `~/.ssh/authorized_keys`. Use the
`generic-ssh` provider (the default when no `provider` is set) - it works on any
host you can already reach:

```sh
sshmgr host add development web1 --hostname 203.0.113.10 --user deploy   # provider defaults to generic-ssh
sshmgr reconcile
sshmgr deploy development_web1-ed25519   # ADD via ssh-copy-id
sshmgr rotate development_web1-ed25519   # ROTATE: stage -> ssh-copy-id new -> verify login -> revoke old
```

**Removal is hardened** (it edits the file that controls who can log in): before
any change it **backs up** `authorized_keys` on the server, dedups by key body,
**refuses to leave the file empty** (lockout guard), and writes **atomically**
(temp + `mv`) so a dropped connection can't corrupt it.

> Always keep your current SSH session open and test a fresh login in a second
> terminal before closing it - a backup on the server is useless if you can't
> get in to restore it.

---

## 3. GCP, AWS, and others (no built-in API adapter yet)

These have non-standard key models; use the **server-keys** path above for live
instances, or their own tooling for project/account-level keys:

### Google Cloud (GCE)
- **Per-instance / per-project metadata or OS Login.** For a running VM, the
  server-keys path (`generic-ssh`) works once you can SSH in.
- **Account/project level** (so new VMs get the key):
  ```sh
  # OS Login (recommended):
  gcloud compute os-login ssh-keys add --key-file=~/.ssh/profiles/<p>/<key>.pub
  gcloud compute os-login ssh-keys remove --key=<fingerprint>
  # or project metadata (legacy):
  gcloud compute project-info add-metadata --metadata-from-file ssh-keys=keys.txt
  ```

### AWS EC2
- **Key pairs are set only at launch** and can't be changed on a running
  instance - so for an existing instance, use the **server-keys** path
  (`generic-ssh`) or **EC2 Instance Connect** to push a temporary key.
- The EC2 "key pair" itself: `aws ec2 import-key-pair` / `delete-key-pair`
  (affects *future* launches, not running instances).

### Azure, Oracle Cloud, OVH, etc.
- Running instance → **server-keys** (`generic-ssh`).
- Account/project keys → add a `kind: rest` entry (no code) if they have a REST
  key API, else `provider: manual` / web-panel with the console URL.

A brand-new provider with a REST API can be added either with **no code**
(`kind: rest`, see [providers.md](providers.md#add-a-rest-provider-with-no-code-kind-rest))
or as a first-class adapter in `providers/cloud.py` (subclass `RestVpsProvider`).

---

## 4. Locked out? Break-glass recovery

If you can't SSH in at all, get to the server another way - your provider's
**web/recovery console** (DigitalOcean Recovery Console, GCP serial/browser SSH,
Hetzner console, ...) - and use `sshmgr recover`:

```sh
# Tailored snippet: re-add ONE specific key to authorized_keys. Paste into the console.
sshmgr recover work_web1-ed25519

# No argument: the full interactive recovery tool (list/add/remove/fix-perms/diagnose).
sshmgr recover
```

`recover <key>` prints a self-contained `sh` snippet (the key's public half
embedded) that backs up `authorized_keys`, dedups, re-adds the key, and fixes
perms - paste it into the console and you're back in. `recover` with no argument
prints the full `fixkeys` menu (reads from `/dev/tty`, so pasting the whole
script still works; no SSH or Python needed on the server).

> After recovering, open a **second** terminal and confirm a fresh SSH login
> before closing the console.

---

## Appendix: VPS-tool parity

Every feature of the original standalone VPS key tool has a home in ssh-manager:

| Original tool (`providers.py` / `serverkeys.py` / `vpskeys.py` / `fixkeys.sh`) | ssh-manager |
|---|---|
| `Provider` REST base (token, session, retry/backoff) | `providers/cloud.py::RestVpsProvider` + `util/http.py` (stdlib urllib + retry) |
| `DigitalOcean` / `Vultr` / `Hetzner` / `Linode` / `Scaleway` | same-named adapters in `providers/cloud.py` |
| `list_keys` | `verify` / `list_deployed` |
| `add_key` | `deploy` (idempotent; renames a stale ssh-manager title) |
| `rename_key` | `rename` (+ auto on re-deploy) |
| `delete_key` | `remove` (matched by key body) |
| `GenericSpec` + `config.json` `extra_providers` (no-code provider) | `kind: "rest"` + `rest` block in `providers.json` (`providers/cloud.py::GenericRest`) |
| `available_providers` (which tokens are set) | `sshmgr providers` |
| `KEY_TYPES`, `_split_key_line`, `_looks_like_base64`, `key_body`, `same_key`, `is_valid_public_key`, `count_keys`, `add/remove_key_from_text` | `core/authorized_keys.py` (stricter: validates the base64 wire-type) |
| `Server` read/write `authorized_keys` (backup, atomic, lockout guard) | `providers/ssh_generic.py` (`generic-ssh`) |
| `Server.fix_permissions` | `fixkeys.sh` menu **4. fix permissions** (shipped + emitted by `sshmgr recover`) |
| Account-keys interactive menu | `deploy` / `rotate` / `remove` / `rename` + `tui` |
| Server-keys interactive menu | `generic-ssh` deploy/revoke + the `recover` recovery tool |
| `fixkeys.sh` (paste-into-console recovery) | shipped as package data; `sshmgr recover [key]` |
| `.env.example` tokens | `.env-example` (DIGITALOCEAN_TOKEN / VULTR_API_KEY / HCLOUD_TOKEN / LINODE_TOKEN / SCW_SECRET_KEY + SCW_PROJECT_ID) |
| `requirements.txt` (`requests`) | none - stdlib `urllib` (smaller supply-chain surface) |

The original tool can be retired; nothing it did is missing here.
