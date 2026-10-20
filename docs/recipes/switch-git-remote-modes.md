# Switch checkouts to profile SSH (or back to HTTPS)

Move a tree of checkouts from HTTPS to each owner's own SSH key, safely, and step back if you need to.

Map owners to profiles once, in the manifest:

```jsonc
"defaults": {"git": {"profile": "imanimanyara", "orgs": {"simtabi": "imanimanyara", "laranail": "imanimanyara"}}}
```

Then preview, apply, and check:

```sh
sshmgr git use profile ~/Artisan/projects/opensource/simtabi/packages/* --dry-run
sshmgr git use profile ~/Artisan/projects/opensource/simtabi/packages/* --yes
sshmgr git status ~/Artisan/projects/opensource/simtabi/packages/*
```

Each new URL is checked with `git ls-remote` before `origin` changes, so a checkout whose key is not on
the account stays on its old remote and is named in the error. To go back: `sshmgr git use https …`.

Plain `git@github.com` remotes (`ssh` mode) use the `defaults.git.profile` key through the rendered
`Host github.com`; client repositories belong in `profile` mode, so they never use your key.

Reference: [`git`](../tools/git.md).

---

[← Docs index](../../README.md#documentation)
