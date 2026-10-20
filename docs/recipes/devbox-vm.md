# Use a local VM as a devbox

Reach a Parallels, VMPal, VMware, UTM or Lima VM by name, whatever IP it booted with, and point Docker at it.

```sh
sshmgr vm list                                   # find the VM's name
sshmgr profile add devbox --category personal
sshmgr vm add devbox devbox --hypervisor vmpal --vm "Ubuntu 24.04" -u imani
sshmgr reconcile                                 # mint devbox_devbox-ed25519
```

Install the public key in the guest once, for example through the hypervisor:

```sh
vmpal exec "Ubuntu 24.04" -- sh -c 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys' \
  < ~/.ssh/profiles/personal/devbox/devbox_devbox-ed25519.pub
```

Then connect, and give Docker a context:

```sh
ssh devbox                      # starts the VM if it is stopped
sshmgr vm docker-context devbox
docker --context devbox ps
```

OrbStack and Podman keep their own SSH and keys; use their contexts instead.

Reference: [`vm`](../tools/vm.md).

---

[← Docs index](../../README.md#documentation)
