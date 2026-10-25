# `export` — copies of the config for other tools

Two commands write a copy of the managed config for a tool that cannot read the split layout: `config export --flat`
for anything that reads one `ssh_config`, and `termius export` for the Termius app.

Both are opt-in and read-only towards `~/.ssh`. They write under `~/.config/ssh-manager/exports/` (mode 0600, since
the files list every host and key path), and they refuse any target inside `~/.ssh`, however the path is spelled: containment is
checked by inode, so another case on APFS or a symlinked directory is caught too. The split config, `~/.ssh/config` and `profiles/<category>/config`, stays exactly as it was.

## Why a flat copy

With [categories](../recipes/group-profiles-into-categories.md), `~/.ssh/config` holds `Match all` and one `Include`
per category, and the hosts live in the included files. OpenSSH follows that; some importers do not. Termius reads only
the top-level file, so it finds no hosts there and falls back to bare addresses from `known_hosts`, with no user or key.

## `sshmgr config export --flat`

```bash
sshmgr config export --flat                     # ~/.config/ssh-manager/exports/ssh_config
sshmgr config export --flat --out ~/flat.conf   # another file
sshmgr config export --flat --out -             # stdout
```

| In the export | Value |
|---|---|
| Hosts | every profile's hosts inline, in manifest order, whatever their category |
| Order | the git ssh-mode `Host github.com` after the profiles, `Host *` last, as `config render` orders them |
| Paths | every `~/.ssh/...` and `~/...` made absolute (`IdentityFile`, `UserKnownHostsFile`, `IdentityAgent`, path-valued raw options) |
| Not present | `Include`, `Match`, the managed header (a copy must never be mistaken for a file sshmgr owns) |

`ssh -G -F <export> <alias>` resolves a host from the copy the same way `ssh -G <alias>` does from the real config. The
copy goes stale when the manifest changes; export again rather than editing it.

## `sshmgr termius export`

Termius keeps hosts in its own encrypted vault and has no command line or API to add them, so sshmgr cannot write into
it. It writes the CSV Termius's importer reads instead:

```bash
sshmgr termius export                      # ~/.config/ssh-manager/exports/termius-hosts.csv
sshmgr termius export --open               # macOS: also open Termius and show the file in Finder
sshmgr termius export --skip unc           # leave a host out (repeatable)
sshmgr termius export --include-git        # also git hosts
sshmgr termius export --out - > hosts.csv  # CSV on stdout, the report on stderr
```

| Column | Value |
|---|---|
| `Groups` | the profile |
| `Label` | the host alias |
| `Tags` | the host's tags (a comma inside one tag becomes a space) |
| `Hostname/IP` · `Port` · `Username` | from the host; `Protocol` is `ssh` |
| `Password` | always empty |

Left out, and listed under `skipped:`:

- **VM hosts** — reached only through sshmgr's ProxyCommand, which Termius ignores;
- **git hosts** — user `git`, or a `github`/`gitlab` provider: not shells (`--include-git` adds them);
- **`--skip` aliases** — an alias that names no host is an error, not a silently ignored typo.

A value starting with `=`, `+`, `-` or `@` is prefixed with `'`, so the file cannot run a formula if opened in a
spreadsheet.

**The CSV carries no keys.** Termius's CSV import takes labels, addresses, ports, groups, tags and credentials but has
no key column ([Import existing hosts](https://docs.termius.com/getting-started/import-existing-hosts)); keys live in Termius's Keychain and are linked to each host
([Keychain](https://support.termius.com/hc/en-us/articles/4401872025113-Keychain), [SSH keys and certificates](https://docs.termius.com/keychain/ssh-keys-and-certificates)). The export prints each host's key path, then:

## `sshmgr termius keys`

```bash
sshmgr termius keys                              # every exported host: HOST, TERMIUS LABEL, PRIVATE KEY path
sshmgr termius keys dani-prd-db-00               # copy its private key to the clipboard, print the label
sshmgr termius keys dani-prd-db-00 --clear-after 60s   # ...and empty the clipboard after 60 seconds
sshmgr termius keys --clear                      # empty the clipboard now
sshmgr termius keys dani-prd-db-00 --print       # key on stdout instead (warns on stderr; avoid)
sshmgr termius keys github-me --include-git      # git hosts, as with export --include-git
```

The label is the key file's name (`adelsaiq_dani-prd-db-00-ed25519`). The key is copied with `pbcopy` (macOS),
`wl-copy`, `xclip` or `xsel` (Linux), or `clip` (Windows), and never printed without `--print`. In Termius:
**Keychain → New Key** (or **Add key** on SSH key selection), Label = the label, paste into **Private key**, leave
**Certificate** empty, **Save**; pick it on the host and **Continue & Save**. A key kept in 1Password is refused, to
add from 1Password instead. Full walk-through: [Import your hosts into Termius](../recipes/import-hosts-into-termius.md).

The column layout is the one third-party exporters reproduce from Termius's import template (Termius 9.x). Termius
publishes the template only inside the app (Hosts → New Host → Import → CSV → download template); if its header ever
differs, `TermiusColumns` in `src/internal/core/renderer/export.go` is the one place to change.

---

[← Docs index](../../README.md#documentation)
