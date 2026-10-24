# Import your hosts into Termius

Termius's SSH-config import does not follow `Include`, so a categorized setup shows up as bare addresses with no user
or key. Import the CSV sshmgr writes instead.

```bash
sshmgr termius export --open
```

1. In Termius: **Hosts → New Host (arrow) → Import → CSV**, and choose `termius-hosts.csv` (Finder shows it with
   `--open`; it lives in `~/.config/ssh-manager/exports/`).
2. For each key the command listed, **Keychain → Import key** from that path, once.
3. Open each imported host and pick its key in the **SSH key** field.

Delete the hosts an earlier `~/.ssh` import created from `known_hosts` (bare IPs, no user) so they are not mistaken for
the real ones. Re-run the export after adding or editing hosts; the CSV is a copy, not a link.

For a tool that reads one `ssh_config` file rather than a CSV, `sshmgr config export --flat` writes every host inline.

Reference: [`export`](../tools/export.md).

---

[← Docs index](../../README.md#documentation)
