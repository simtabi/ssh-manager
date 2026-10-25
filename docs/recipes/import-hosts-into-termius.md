# Import your hosts into Termius

Termius's SSH-config import does not follow `Include`, so a categorized setup shows up as bare addresses with no user
or key. Import the CSV sshmgr writes instead.

```bash
sshmgr termius export --open
```

1. In Termius: **Hosts → New Host (arrow) → Import → CSV**, click **Skip download**, and choose `termius-hosts.csv`
   (Finder shows it with `--open`; it lives in `~/.config/ssh-manager/exports/`).
2. **The CSV carries no SSH keys.** Termius's CSV template has no key column, so every imported host arrives with no
   key, and connecting stops at **SSH key selection**. For each host, once:
   1. `sshmgr termius keys <HOST>` copies that host's private key to the clipboard (never shown) and prints the
      label to use, the key file's name, e.g. `adelsaiq_dani-prd-db-00-ed25519`.
   2. In Termius: **Keychain → New Key** (or **Add key** on the SSH key selection screen). Set **Label** to that
      label, click into **Private key** and paste, leave **Certificate** empty, and **Save**.
      (**Import from key file** works too; press ⌘⇧. to show the hidden `~/.ssh` folder.)
   3. Pick the new key for the host and click **Continue & Save** (or set it in the host's **SSH key** field).
3. Clear the clipboard: `sshmgr termius keys --clear` (or copy with `--clear-after 60s` to do it automatically).

`sshmgr termius keys` with no host lists every exported host with its label and key path. `--print` writes the key to
stdout instead of the clipboard and warns on stderr; avoid it, since the key stays in your scrollback.

Re-running the export after editing hosts gives a fresh CSV; sshmgr cannot see what is already in Termius, and
Termius does not document how a second import treats hosts it already has, so check for duplicates and re-attach a key
if a host shows none.

Sources (checked 2026-10-25): Termius docs [Import existing hosts](https://docs.termius.com/getting-started/import-existing-hosts) (the CSV fields: labels, addresses,
protocols, ports, groups, tags, credentials; no keys), [SSH keys and certificates](https://docs.termius.com/keychain/ssh-keys-and-certificates) (Keychain → New key, Label,
Import from key file), and the support article [Keychain](https://support.termius.com/hc/en-us/articles/4401872025113-Keychain) (paste a PEM/OpenSSH key with its BEGIN/END lines into
**Private Key**; optional **Certificate**; "link the key with the host in the host's properties").

Delete the hosts an earlier `~/.ssh` import created from `known_hosts` (bare IPs, no user) so they are not mistaken for
the real ones. The CSV is a copy, not a link.

For a tool that reads one `ssh_config` file rather than a CSV, `sshmgr config export --flat` writes every host inline.

Reference: [`export`](../tools/export.md).

---

[← Docs index](../../README.md#documentation)
