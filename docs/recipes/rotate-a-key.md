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

For a target that cannot self-verify — a web panel, a provider with no read API —
rotation would abort every time. Say so explicitly:

```sh
sshmgr rotate work/work_gh-ed25519 --allow-unverified
```

> A VPN-gated host that is unreachable aborts the rotation before anything is
> staged, and the message names the VPN. Connect it and retry rather than forcing
> past it.

Reference: [`rotate`](../tools/rotate.md).

---

[← Docs index](../../README.md#documentation)
