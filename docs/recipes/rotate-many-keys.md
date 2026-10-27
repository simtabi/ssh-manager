# Rotate or repair many keys at once

Rotate a whole category, a profile or every key in one command, and rebuild
public keys that went missing or wrong.

See what a batch would do before it does it:

```sh
sshmgr rotate --all --dry-run
```

Rotate by category, profile, host alias or key, in any mix:

```sh
sshmgr rotate --category clients
sshmgr rotate simtabi github-imanimanyara
```

The batch asks once, writes one backup, then rotates each key with the usual
stage, deploy, verify and commit. A key that cannot be verified is left exactly
as it was and named at the end; the others still rotate.

To rebuild `.pub` files from the keys they belong to (from the private key, or
from the vault item for a 1Password profile):

```sh
sshmgr key regen-pub --all --dry-run
sshmgr key regen-pub --all
```

A `.pub` reported as `rewritten` was a different key, so redeploy anything you
set up from it: `sshmgr deploy <key>`.

Full reference: [`rotate`](../tools/rotate.md#rotating-a-batch) ·
[`key regen-pub`](../tools/validate.md).

---

[← Docs index](../../README.md#documentation)
