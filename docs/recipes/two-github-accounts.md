# Two GitHub accounts on one machine

The case profiles exist for: one hostname, two identities, and neither able to
authenticate as the other.

```sh
sshmgr profile add personal
sshmgr profile add work
sshmgr host add personal github-personal -H github.com -u git --provider github
sshmgr host add work     github-work     -H github.com -u git --provider github
sshmgr reconcile
```

That mints two keys and writes two `Host` blocks against the same hostname, each
with its own `IdentityFile` and a per-host `IdentitiesOnly yes` — so a connection
to `github-work` is never offered the personal key, and vice versa.

Point each repository at the alias rather than the hostname:

```sh
git remote set-url origin git@github-work:acme/service.git
```

Or make it automatic for a whole directory, in `~/.gitconfig`:

```gitconfig
[includeIf "gitdir:~/code/work/"]
    path = ~/.gitconfig-work
```

```gitconfig
# ~/.gitconfig-work
[url "git@github-work:"]
    insteadOf = git@github.com:
```

Deploy both public keys and confirm which key each alias resolves to:

```sh
sshmgr deploy personal_github-ed25519
sshmgr deploy work_github-ed25519
sshmgr config show github-work        # ssh -G for that alias
```

Full manifest reference: [Configuration](../configuration.md).

---

[← Docs index](../../README.md#documentation)
