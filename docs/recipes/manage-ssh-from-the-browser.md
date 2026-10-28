# Manage SSH from the browser

Open the web UI, make a change after seeing exactly what it writes, and run a deploy or a rotation with its output on screen.

## Start it

```sh
sshmgr serve
```

It opens a browser at `http://127.0.0.1:7822/?token=…` and listens on this machine only. To try it
on a sandbox first, so nothing touches your real `~/.ssh`:

```sh
sshmgr --dev-root ~/sshmgr-sandbox serve
```

## Make a change

1. Fill in a form: add a host on **Hosts**, or tick *and its key files* next to a profile on
   **Profiles** to delete one completely.
2. **Preview.** The page shows the command it stands for, what sshmgr would say, and a diff of every
   file the change would write. Private keys it would delete or move are listed by path.
3. **Make this change.** If anything moved since the preview, from a terminal or another tab, the
   page shows the new preview instead of writing.

Each change is in **History**, with source `web`.

## Deploy or rotate a key

1. Open the key on **Keys**, then **Deploy**, **Rotate** or **Roll back**.
2. Review what the job will do, then run it. The output shows as it comes.
3. A target that takes the key by hand, such as a panel, pauses a rotation with the new public key
   to copy. Paste it there, then **Done, carry on**.

A rotation writes an encrypted backup first, so set `SSH_MANAGER_AGE_RECIPIENT` before you start
`sshmgr serve`. A target that needs a password is deployed from a terminal: `sshmgr deploy <key>`.

## Look without changing anything

```sh
sshmgr serve --read-only
```

The pages show no forms and serve no change.

See [`serve`](../tools/serve.md) for every change, job and security setting.

---

[← Docs index](../../README.md#documentation)
