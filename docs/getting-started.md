# Getting started

A first run end to end: from an empty machine to a deployed key, and what each
step is actually doing.

## The mental model

Profiles model **identity**, not technology. `work`, `personal`, `simtabi`,
`development` are profiles; "github" is not. The same hostname can appear in two
profiles and get a different key in each — that is the point, and it is what lets
two accounts on one forge coexist without either being able to authenticate as
the other.

The manifest is the single source of truth. `~/.ssh` is **generated output**:
`reconcile` rebuilds it, and anything the tool did not write is left alone.

## First run

```sh
sshmgr init                  # create ~/.config/ssh-manager (dirs, perms, seed files)
```

`init` seeds an **empty** manifest. Add profiles and hosts before `reconcile`
mints anything — three ways, whichever suits:

```sh
sshmgr profile add work
sshmgr host add work gh -H github.com -u git      # or edit manifest.json directly
sshmgr import ~/.ssh/config                        # or onboard an existing setup
```

Then build the tree:

```sh
sshmgr reconcile --dry-run   # preview: what would be minted, what would be written
sshmgr reconcile             # build ~/.ssh from the manifest
sshmgr config check          # confirm the file matches the manifest (exit != 0 on drift)
```

At this point every declared key exists at `~/.ssh/profiles/<profile>/<key>`,
`~/.ssh/config` holds a managed block with one `Host` entry per host, and
reachable hosts have been pinned into `~/.ssh/known_hosts`.

## Getting a key onto its target

```sh
sshmgr deploy work_gh-ed25519    # ssh-copy-id, gh, glab, a REST API, or manual
sshmgr validate                  # every keypair parses and the halves match
sshmgr doctor                    # deps, perms, agent, pins, drift
```

`deploy` picks its method from the host's provider. Where there is no API — a
web panel, an unknown forge — it prints the page to paste the key into rather
than pretending to have done it.

## Living with it

```sh
sshmgr list --type vcs         # filterable view across profiles
sshmgr show gh                 # manifest, key files, rendered config and pins, reconciled
sshmgr expiry                  # per-key rotation age
sshmgr rotate work_gh-ed25519  # zero-downtime staged rotation
sshmgr notify install          # scheduled reminders before keys come due
```

Most destructive verbs take `--yes`/`-y` to run non-interactively, and the
deletes take `--revoke` to pull the key off its targets as well.

## Passphrases

Off by default, always a conscious choice. `--passphrase` prompts without echo
and confirms; `--no-passphrase` scripts the other answer. The passphrase reaches
`ssh-keygen` through the askpass protocol, never through the command line, so it
does not appear in the process list.

## Safety: what is always on

Every mutating command passes through one guard that takes an advisory lock,
sweeps crash residue, and snapshots `~/.ssh` before changing anything. Combined
with atomic writes, the tree is always left internally consistent and any run is
reversible.

There are four recovery layers, and they are not interchangeable:

| Layer | Recovers | When |
|---|---|---|
| `snapshots restore` | the config tree | an edit went wrong; local, last 10 kept |
| `rollback <key>` | one key's predecessor | a rotation deployed badly |
| `restore <bundle>` | the keys themselves | a new machine, or the old one is gone |
| `recover <key>` | access to a server | you are locked out entirely |

**Snapshots deliberately carry no private keys.** One is written before every
mutating command and several are kept, so a private key in one would be a rolling
plaintext archive of your keys. The encrypted `bundle` is the path that recovers
key material, and `recover` is the break-glass escape hatch that needs no working
SSH at all.

---

[← Docs index](../README.md#documentation)
