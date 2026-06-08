# recover - break-glass when you're locked out

ssh-manager is built so you don't get locked out - but if you do (lost laptop, wiped
`~/.ssh`, a bad `authorized_keys` edit), `recover` is the escape hatch. It needs
no working SSH and no Python *on the server* - you reach the box another way
(your provider's web/recovery console: DigitalOcean Recovery Console, GCP
serial/browser SSH, Hetzner console, ...) and paste.

## `sshmgr recover <key>` - tailored snippet

Prints a small, self-contained `sh` snippet with that key's **public half
embedded** (shell-escaped). Paste it into the console; it backs up
`authorized_keys`, dedups, re-adds the key, and fixes perms:

```sh
sshmgr recover work_web1-ed25519     # copy the output, paste into the server console
```

The body is computed by ssh-manager (not fragile `awk`), and the key line is escaped,
so an arbitrary key comment can't break or inject the script.

## `sshmgr recover` - full interactive tool

With no argument it prints the complete `fixkeys` recovery tool (also shipped in
the wheel as package data). It reads keystrokes from `/dev/tty`, so pasting the
whole script into a console still works, and offers a menu:

1. list keys (with fingerprints)
2. add a key
3. remove a key (with a lockout guard - refuses to leave `authorized_keys` empty)
4. **fix permissions** (`~/.ssh` 700, `authorized_keys` 600, ownership)
5. diagnose login problems (perms, home-dir writability, sshd `PubkeyAuthentication`)

Every change is backed up first and written atomically.

> After recovering, open a **second** terminal and confirm a fresh SSH login
> before closing the console - a backup is useless if you can't get back in.

Related: the `generic-ssh` provider applies the same backup/atomic/lockout-guard
rules when ssh-manager edits `authorized_keys` over SSH (see [vps.md](vps.md)).
