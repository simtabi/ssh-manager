# Host specs: add or update many hosts at once

`sshmgr host apply` takes hosts as one-line specs and upserts them into a
profile:

```text
<alias> <host>[:port] <user> [role]
```

| Field | Meaning |
|---|---|
| `alias` | the name you `ssh` to; also names the key (`<profile>_<alias>-ed25519`) |
| `host` | hostname or IP; `host:port`, `[v6]` and `[v6]:port` also work (port defaults to 22 on add, unchanged on update) |
| `user` | ssh user |
| `role` | optional; stored as a tag |

## One host

```sh
sshmgr host apply adelsaiq dani-prd-web-00 206.189.185.129 ploi web
```

## Many hosts

```sh
sshmgr host apply adelsaiq \
  --host "dani-prd-web-00 206.189.185.129 ploi web" \
  --host "dani-prd-db-00  137.184.219.1   ploi db" \
  --tag prd --reconcile
```

Or keep them in a file and re-run it whenever an IP changes:

```text
# hosts.txt
dani-prd-web-00 206.189.185.129 ploi web
dani-prd-db-00  137.184.219.1   ploi db
bastion         203.0.113.5:2222 admin
```

```sh
sshmgr host apply adelsaiq -f hosts.txt --dry-run   # preview
sshmgr host apply adelsaiq -f hosts.txt --reconcile # apply, then mint keys
cat hosts.txt | sshmgr host apply adelsaiq -f -     # from stdin
```

A JSON array works too, of spec strings or objects:

```json
[
  "dani-prd-web-00 206.189.185.129 ploi web",
  {"alias": "dani-prd-db-00", "host": "137.184.219.1", "user": "ploi", "role": "db", "tags": ["prd"]}
]
```

## What it does

- A new alias is added exactly as `host add` would add it.
- An existing alias gets its hostname, user and (if given) port set, as `host
  edit` would. The role and any `--tag` are merged into its tags; tags are
  never removed.
- Each host is reported `added`, `updated` (with what changed) or `unchanged`.
  Running the same specs again reports everything unchanged.
- The whole batch is validated by the manifest's rules and saved once; a bad or
  duplicated spec changes nothing.
- A missing profile is refused unless you pass `--create-profile` or
  `--category <name>` (which implies it).
- Without `--reconcile`, new hosts have no key until you run `sshmgr
  reconcile`. With it, the reconcile preview is shown and confirmed as usual
  (`-y` skips the prompt; `--no-pin` skips known_hosts auto-pinning).
