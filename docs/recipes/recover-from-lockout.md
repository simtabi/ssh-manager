# Recover from a locked-out server

When SSH no longer works and you can still reach the box another way — a
provider's web console, a serial connection, a rescue image.

From a machine that still works, print the snippet for the key that should be
there:

```sh
sshmgr recover work/work_hpc-ed25519
```

Paste the output into the console. It is POSIX `sh`, needs no working SSH and no
interpreter on the server, backs up `authorized_keys` before it edits, appends
the key only if it is not already present, and leaves the file at 0600.

With no key named, you get the full interactive repair tool instead:

```sh
sshmgr recover > fixkeys.sh
```

It reads its prompts from `/dev/tty` rather than stdin, so pasting the whole
script into a console does not consume its own menu answers. It lists, adds and
removes keys, repairs permissions, and diagnoses why sshd is refusing you.

> Test SSH from a second terminal before closing the console session. That is the
> one thing the snippet cannot do for you.

Reference: [`recover`](../tools/recover.md).

---

[← Docs index](../../README.md#documentation)
