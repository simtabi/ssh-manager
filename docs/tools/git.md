# `git` — switch checkouts between profile SSH, plain SSH and HTTPS

Two verbs: `git status` shows how each checkout's GitHub `origin` authenticates, and `git use` points it at
one of three modes after proving the new URL works.

| Mode | Origin URL | Authenticates as |
|---|---|---|
| `profile` (default) | `git@<profile's alias>:owner/repo.git`, e.g. `git@github-imanimanyara:simtabi/pheg.git` | that profile's GitHub key |
| `ssh` | `git@github.com:owner/repo.git` | the key bound to the rendered `Host github.com` (`defaults.git.profile`) |
| `https` | `https://github.com/owner/repo.git` | your git credential helper (for example `gh-app git-credential`) |

## Choosing the mode

`git use` takes the mode from, in order: the first argument when it names a mode, `--mode`,
`$SSHMGR_GIT_MODE`, `defaults.git.mode` in the manifest, then `profile`.

## Choosing the profile

The repository owner picks the profile: `defaults.git.orgs` (owner → profile, case-insensitive), then
`defaults.git.profile`, then the only profile with a `github.com` host. With several candidates and no
mapping it stops and asks for `--profile` instead of guessing, because the wrong guess pushes as the wrong
account. `--profile` overrides the mapping for one run.

```jsonc
"defaults": {
  "git": {
    "mode": "profile",
    "profile": "imanimanyara",
    "orgs": {"simtabi": "imanimanyara", "laranail": "imanimanyara", "adelsaiq": "dannielagumo"}
  }
}
```

## `sshmgr git status [PATH...]`

```text
$ sshmgr git status ~/Artisan/projects/opensource/simtabi/packages/*
.../pheg      https    simtabi/pheg      profile=imanimanyara (by owner)
.../sshmgr    profile  simtabi/ssh-manager  profile=imanimanyara
.../notes     -  no origin
```

## `sshmgr git use [MODE] [PATH...]`

```sh
sshmgr git use profile ~/code/*/ --dry-run   # show every rewrite, change nothing
sshmgr git use profile ~/code/*/ --yes       # rewrite, each URL checked first
sshmgr git use https .                        # back to HTTPS in this checkout
SSHMGR_GIT_MODE=ssh sshmgr git use .          # one-off override of the default
```

What it does per checkout:

1. Reads `origin`. No origin, or an origin that is not GitHub (GitLab, another host's alias), is skipped
   and said so.
2. Builds the URL for the mode. `ssh` mode needs `defaults.git.profile`; `profile` mode needs the
   profile to have a `github.com` host.
3. Runs `git ls-remote` against the new URL, with prompts off and SSH in batch mode. Only if that works
   is `origin` rewritten; otherwise the checkout is left as it was and named in the error. A 1Password
   key whose app is locked fails here, before anything changes.

`--dry-run` stops after step 2. The command exits non-zero if any checkout was left unchanged by an error.

Glob `packages/*`, not `*/`, where parked copies share names with live ones.

---

[← Docs index](../../README.md#documentation)
