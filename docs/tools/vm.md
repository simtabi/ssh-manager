# `vm` — local VMs as SSH hosts

A VM's address comes from its hypervisor and changes, so a VM host does not carry one. Its block renders
`ProxyCommand "<sshmgr>" vm proxy <alias>`, and each connection asks the hypervisor where the VM is now.

| Hypervisor | CLI | Address from | Key install | Keys owned by |
|---|---|---|---|---|
| Parallels Desktop | `prlctl` | `list --all --full --json` (`ip_configured`) | `prlctl exec` | sshmgr |
| VMPal | `vmpal` | `list --json` (`localAddress`) | `vmpal exec` | sshmgr |
| VMware Fusion / Workstation | `vmrun` | `getGuestIPAddress -wait` | over SSH once (guest commands need guest credentials) | sshmgr |
| UTM | `utmctl` | `ip-address` (first IPv4) | `utmctl exec` | sshmgr |
| Lima | `limactl` | `list --json` (forwarded `sshLocalPort` on loopback) | `limactl shell` | sshmgr |
| OrbStack | `orb` | its own ssh config (`ssh <machine>@orb`) | not needed | OrbStack |
| Podman machine | `podman` | `machine list --format json` (forwarded port) | not needed | Podman |

OrbStack and Podman run their own SSH access and keys: `vm list` shows their machines, and they are
refused as hosts so sshmgr never takes their keys over. VMware's VM name is the path of its `.vmx`.

## `sshmgr vm list`

```text
parallels  not installed
vmpal      Ubuntu 24.04                   running  host devbox/devbox
vmware     not installed
lima       default                        Running
```

## `sshmgr vm add <profile> <alias> --hypervisor H --vm NAME -u USER`

Adds the host (HostName is the alias, since ProxyCommand ignores it) and re-renders the config. Mint
its key with `sshmgr reconcile`, then install the public key in the guest once (with the hypervisor's
exec, or over SSH with a password).

```sh
sshmgr vm add devbox devbox --hypervisor parallels --vm "Ubuntu 24.04" -u imani
sshmgr reconcile
ssh devbox
```

In the manifest:

```jsonc
{"alias": "devbox", "hostname": "devbox", "user": "imani", "key_name": "devbox_docker-ed25519",
 "vm": {"hypervisor": "parallels", "name": "Ubuntu 24.04"}}
```

A `port` other than 22 on the host wins over the hypervisor's (Lima and Podman forward their own).

## What `vm proxy` does (ssh runs it)

1. Finds the host's VM and hypervisor.
2. Asks for the current address. A stopped VM is started, and sshmgr waits up to three minutes for an
   address, saying so on stderr.
3. Connects and relays stdin/stdout, so ssh talks to the guest as if directly.

The rendered path prefers the `sshmgr` on your `PATH` (a package manager's stable link) over the
versioned file behind it. If an upgrade still moves it, `doctor` reports `vm proxy: … does not exist`
and `sshmgr config render` rewrites it.

## `sshmgr vm docker-context <alias>`

Creates (or updates) a Docker context `ssh://<alias>`, so `docker --context devbox ps` runs against the
VM's daemon through the same ProxyCommand. OrbStack and Podman provide their own contexts.

---

[← Docs index](../../README.md#documentation)
