# Use a GitHub machine user

Give an organization one SSH key that can read every repository, and rotate it
in one command.

A GitHub organization cannot hold an SSH key, and a deploy key belongs to
exactly one repository: GitHub refuses the same public key on a second one. A
machine user is an ordinary GitHub account used only by automation. Put it in a
team with **Read** on the repositories it needs, and its single key reaches all
of them.

## A GitHub App is not a substitute for SSH

A GitHub App (for example one that opens pull requests from CI, or supplies
`git` credentials over HTTPS) cannot hold an SSH key: Apps authenticate with
short-lived tokens over HTTPS only. If every `git` remote uses HTTPS with an
App's token, no SSH key and no machine user is needed. A machine user is for
the case where something must use SSH: an SSH remote, a deploy pipeline that
only speaks SSH, or a server that pulls with a key.

## Set it up

1. Create the account (for example `simtabi-bot`) with an inbox you control,
   and turn on two-factor authentication.
2. In the organization, create a team (for example `bots-read`) with **Read**
   access to the repositories, and add the account to it.
3. Create a token for the machine user that can manage its SSH keys: a
   fine-grained token with the account permission *Git SSH keys: read and
   write*, or a classic token with `admin:public_key`.
4. Store the token where sshmgr can read it, in `~/.config/ssh-manager/.env`:

   ```sh
   GH_TOKEN_SIMTABI=op://Simtabi/simtabi-bot/token
   ```

5. Wire a host to it in the manifest, with `provider` and `token_env`:

   ```jsonc
   {"alias": "github-simtabi", "hostname": "github.com", "user": "git",
    "provider": "github", "token_env": "GH_TOKEN_SIMTABI",
    "key_name": "simtabibot_github-ed25519"}
   ```

6. Add the key to the account and check it:

   ```sh
   sshmgr reconcile
   sshmgr deploy simtabibot_github-ed25519
   ssh -T git@github-simtabi      # Hi simtabi-bot! ...
   ```

Use the alias in remotes: `git@github-simtabi:simtabi/ssh-manager.git`.

## Rotate it

```sh
sshmgr rotate simtabibot_github-ed25519
```

The new key is added to the account, verified, and the old one removed through
the API. Verify also checks that GitHub greets the new key as the account the
token belongs to, so a token for the wrong account fails the rotation instead of
committing a key the alias cannot use.

To keep the private key out of `~/.ssh` as well, give the profile
`key_store: 1password`; see [Keep keys in 1Password](keep-keys-in-1password.md).

---

[← Docs index](../../README.md#documentation)
