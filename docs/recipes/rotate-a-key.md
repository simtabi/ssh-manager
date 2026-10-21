# Rotate a key with no downtime

Replace a key without a window where neither the old nor the new one works.

```sh
sshmgr expiry                        # what is due
sshmgr rotate work/work_gh-ed25519   # stage, deploy, verify, then commit
```

Rotation mints the replacement into `.staging/`, deploys it to every target, and
**only commits if every target verified**. If one does not, the staged key is
discarded, pulled back off anything it reached, and the active key is left
byte-for-byte as it was.

The superseded key moves to `profiles/<profile>/old/` — one predecessor per key,
so there is always exactly one step back:

```sh
sshmgr rollback work/work_gh-ed25519
```

For a hosting panel target (Ploi, Forge, cPanel), run it at a terminal with the
panel open: `rotate` shows the new public key, waits while you paste it, then
logs in with it before replacing the old key. Remove the old key from the panel
afterwards; the report says where.

```sh
sshmgr rotate simtabi/simtabi_oribi-web-ed25519
```

A target that cannot be proven at all (a git web panel, a provider with no read
API) aborts every time; say so explicitly, knowing the new key is committed
before anything proves it:

```sh
sshmgr rotate work/work_gh-ed25519 --allow-unverified
```

> A VPN-gated host that is unreachable aborts the rotation before anything is
> staged, and the message names the VPN. Connect it and retry rather than forcing
> past it.

Reference: [`rotate`](../tools/rotate.md).

---

[← Docs index](../../README.md#documentation)
