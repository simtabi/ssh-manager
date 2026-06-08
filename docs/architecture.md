# Architecture

```mermaid
flowchart TD
    CLI[cli.py · typer] --> F[SshManagerService · Facade]
    TUI[tui.py · questionary] --> F
    CLI --> R[render.py · rich]
    TUI --> R
    F --> SVC[services: reconciler · deployer · rotator · bundler · notifier · editor]
    F --> CORE[core: manifest · renderer · inventory · key · expiry]
    SVC --> PROV[providers · Strategy<br/>github · gitlab · web-panel · ssh]
    SVC --> PLAT[platforms · Strategy<br/>macOS · linux · windows]
    SVC --> UTIL[util: fs · perms · proc · lock · jsonstore]
    CORE -->|single source of truth| MAN[(manifest.json)]
    SVC -->|generated output| SSH[(~/.ssh)]
```

```
src/ssh_manager/
  cli.py            # typer; thin - parse args, call the Facade (no logic)
  tui.py            # interactive surface (rich+questionary, Prompter seam) - over the Facade
  render.py         # rich presentation (tables/trees/panels/icons) over service data
  core/             # pure domain: manifest, key, inventory, renderer, expiry
  services/         # use-cases: facade, reconciler, configsvc, importer, deployer, rotator,
                    #   notifier, bundler, editor, knownhosts, query, keystore, agent, preflight
  providers/        # Strategy: github, gitlab, cloud(DO/Vultr/Hetzner/Linode/
                    #   Scaleway/GenericRest), ssh_generic, registry, base
  platforms/        # Strategy: macos + linux (first-class), windows + detect()
  data/             # fixkeys.sh (break-glass recovery, shipped in the wheel)
  util/             # fs, perms, proc, http, log, lock, jsonstore, paths, errors
  templates/        # jinja2: root_config.j2, profile_config.j2
config/             # source-of-truth defaults: example manifest/inventory + the
                    #   providers catalog (packaged; the shipped default) + schema/.
                    #   live home = OS-standard ssh-manager dir, see util/paths + platforms
```

## Key flows

### Home + config resolution (manifest first; user, else shipped default)

```mermaid
flowchart TD
    S[command starts] --> O{SSH_MANAGER_HOME or<br/>SSH_MANAGER_CONFIG_DIR set?}
    O -- yes --> OV[home = override, absolutized]
    O -- no --> STD[home = OS-standard ssh-manager dir<br/>XDG_CONFIG_HOME/ssh-manager or ~/.config/ssh-manager<br/>APPDATA/ssh-manager on Windows]
    STD --> MIG{legacy ~/.sshmgr exists<br/>AND new home absent?}
    MIG -- yes --> MOVE[migrate: move ~/.sshmgr to home]
    MIG -- no --> R[resolved home]
    MOVE --> R
    OV --> R
    R --> MANI{manifest.json in home?}
    MANI -- yes --> SRC[use it: single source of truth]
    MANI -- no --> EI[error: run sshmgr init]
    R --> CAT{providers.json in home?}
    CAT -- yes --> UC[user catalog]
    CAT -- no --> SP[shipped package catalog<br/>always accurate]
```

### Mutation guard (wraps every state-changing verb)

```mermaid
flowchart LR
    V[mutating verb] --> LK[acquire advisory lock]
    LK --> SW[sweep crash residue<br/>stale .tmp / .staging]
    SW --> SN[snapshot ~/.ssh into snapshots/]
    SN --> OP[run the operation]
    OP --> AW[atomic writes + set perms]
    AW --> UL[release lock]
```

### reconcile: manifest to ~/.ssh

```mermaid
flowchart TD
    MAN[manifest] --> PLAN[plan: keys present vs missing]
    PLAN --> MINT[mint missing keys<br/>flagged needs-redeploy]
    MINT --> REN[render config + profiles config<br/>foreign blocks preserved]
    REN --> PER[set perms 700 / 600 / 644]
    PER --> PIN[auto-pin reachable hosts known_hosts]
    PIN --> GV[validate with ssh -G]
```

### rotate: zero-downtime, single-old-archive

```mermaid
stateDiagram-v2
    [*] --> Preflight
    Preflight --> Staging: all SSH targets reachable
    Preflight --> Aborted: a target is unreachable
    Staging --> DeployVerify: mint staged key
    DeployVerify --> Commit: every target verified<br/>(or --allow-unverified)
    DeployVerify --> Aborted: verify failed
    Commit --> [*]: purge old, archive current,<br/>promote staged, revoke old, reset inventory
    Aborted --> [*]: staged pulled back + discarded,<br/>active key untouched
```

## Everything lives under the profile (and securely)

`~/.ssh` is **generated output**, organized so that everything belonging to one
identity sits under that identity's profile dir - and nothing crosses profiles:

```
~/.ssh/
├── config                         # marked ssh-manager block (Include + global Host*);
│                                   # foreign content (e.g. OrbStack) outside it is kept
└── profiles/
    ├── work/
    │   ├── config                 # 600 - this profile's Host blocks
    │   ├── known_hosts            # 644 - this profile's OWN host-key trust store
    │   ├── work_unc-ed25519       # 600 - private key, never leaves the machine
    │   ├── work_unc-ed25519.pub   # 644 - public key
    │   ├── old/                   # ≤1 archived predecessor per key (rotation)
    │   └── .staging/              # transient, only mid-rotation
    ├── personal/  ...  (github.com via its own key + known_hosts)
    └── simtabi/   ...  (github.com again, but a SEPARATE key + known_hosts)
```

Per-profile isolation is enforced by the rendered config:

- `IdentityFile ~/.ssh/profiles/<p>/<key>` + `IdentitiesOnly yes` → a host is only
  ever offered **its own** key (no cross-offer, no lockouts).
- `UserKnownHostsFile ~/.ssh/profiles/<p>/known_hosts` → host-key trust is scoped
  to the identity; trusting `github.com` as `personal` never trusts it as `simtabi`.
- Perms are load-bearing and uniform (dirs 700, private keys + config 600, public
  keys + known_hosts 644), set on create and re-asserted by `doctor`/`reconcile`.

The manifest is the single source of truth; `reconcile` regenerates this whole
tree from it (and `restore` brings the same keys back from an age bundle).

## Patterns

- **Facade** (`services/facade.py`) - the one API the CLI/TUI/desktop call.
- **Strategy** - `providers/` (deployment adapters) and `platforms/` (OS behaviour).
- **Repository** - `Manifest` / `Inventory` load/save through the atomic JSON store.
- **Command** - one CLI verb per use-case. **Factory** - key/provider creation.

## Load-bearing rules

- **One renderer.** `config render`, `config check`, and `reconcile` all call
  `core/renderer.render_all`. `check` renders to a buffer and compares
  byte-for-byte, so the verifier and the writer can never disagree.
- **Atomic + locked state.** All state/config writes go through
  `util/jsonstore` + `util/fs` (temp + `os.replace`) under `util/lock`.
- **Perms via the platform layer.** `platform.set_perms` is the single chokepoint
  for `chmod`/ACLs; `util/perms.mode_for` owns the path→mode policy.
- **Subprocess chokepoint.** Every shell-out goes through `util/proc` (argv lists,
  never `shell=True`).
- **One mutation at a time.** The advisory lock is held for the whole mutating
  verb, including provider network calls in `deploy`/`rotate`/delete (so a
  single-user run is serialized and can't interleave). Every `ssh`/CLI/HTTP call is
  hard-timeout-bounded, so a slow provider blocks other invocations only for that
  bounded window, never indefinitely.

## Platform layer

`platforms.detect()` returns the OS strategy. `emits_use_keychain` decides whether
the renderer emits the macOS-only `UseKeychain` line; `first_class` drives the
preflight "support in progress" note. **macOS, Linux, and Windows are all
first-class.** Each is validated on its own CI runner: Linux (systemd-user timer /
cron scheduler, `notify-send`), and Windows (`icacls` owner-only ACLs, `schtasks`,
PowerShell toast) - the latter via real-binary tests plus a full
reconcile/perms/config end-to-end on the windows-latest runner.
