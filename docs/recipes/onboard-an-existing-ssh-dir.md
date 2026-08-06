# Onboard an existing `~/.ssh`

Bring a hand-built setup under management without regenerating anything.

```sh
sshmgr init                      # create the home (seeds an EMPTY manifest)
sshmgr import ~/.ssh/config      # read the config into the manifest
sshmgr diff                      # what would change, before anything does
sshmgr reconcile
```

`import` parses your config — including `Include` directives — and derives a
profile per `IdentityFile` path, falling back to `imported`. A key that already
lives under `profiles/<name>/` is referenced where it is; one outside the managed
tree is **copied** in, never moved, and the copy is made owner-only whatever mode
the original had.

> Nothing is regenerated. `import` never mints over an existing key, so the
> identities your servers already trust keep working.

Review before reconciling — the derived profile names are a guess:

```sh
sshmgr list
sshmgr profile edit imported --key-scope per_service
```

A second `import` replaces the manifest, so it is safe to re-run after editing
the source config. It will not overwrite keys it adopted the first time.

---

[← Docs index](../../README.md#documentation)
