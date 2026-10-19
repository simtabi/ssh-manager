# Group profiles into categories

File profiles under a category directory, such as `internal`, `clients` or
`others`, and give each category its own `config` file.

```sh
sshmgr profile edit personal --category internal
sshmgr profile edit adelsaiq --category clients
sshmgr profile edit work     --category others
```

Each edit moves the profile's key directory from `profiles/<profile>/` to
`profiles/<category>/<profile>/`, re-points its inventory records, and
re-renders. The profile's `Host` blocks move out of the root config into
`profiles/<category>/config`, and the root config's managed block now opens
with one `Include` per category:

```
# Managed by ssh-manager - do not edit (run: sshmgr config render)

Match all
Include ~/.ssh/profiles/internal/config
Include ~/.ssh/profiles/clients/config
Include ~/.ssh/profiles/others/config

Host *
    ...
```

`Match all` keeps the Includes global. Without it, a `Host` block you keep above
the managed block would scope every category to that one host. Uncategorized
profiles stay inline in the root config, as before.

New profiles take the flag too: `sshmgr profile add acme --category clients`.
`--category ""` returns a profile to the flat layout.

## If you already moved the directories by hand

`profile edit --category` handles this case as well. When the key directory is
already at the new location, it leaves the files alone and only updates the
manifest and the inventory. Until you run it:

- `sshmgr doctor` reports each moved key as untracked, with where the manifest
  expects it. Its missing finding says not to reconcile.
- `sshmgr reconcile` refuses to run and names the key's real location, rather
  than minting a replacement for a key that is still deployed.

A `profiles/<category>/config` you wrote by hand is never pruned. sshmgr deletes
a `profiles/*/config` only when it carries the managed header or sits in a flat
profile directory, which is where v1 wrote its per-profile files. Once the
manifest names that category, `config render` replaces your file with the
rendered one; a snapshot is taken first.

If your root config has no managed block yet, sshmgr appends one below your
existing content. Remove your own `Include profiles/...` lines and `Host *`
block first if you want only the managed copy.

Full reference: [Configuration](../configuration.md#categories).

---

[← Docs index](../../README.md#documentation)
