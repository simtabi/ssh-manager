"""Typer CLI - a thin shell over the service Facade.

Every verb only parses args and calls the Facade; no business logic lives here.
"""
from __future__ import annotations

import contextlib
from pathlib import Path

import typer

from . import __version__, render
from .services.facade import SshManagerService
from .services.query import ProfileSummary
from .util.errors import SshManagerError

_console = render.console()

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="Profile-based SSH key & config lifecycle manager.")
config_app = typer.Typer(no_args_is_help=True, help="Render/verify ~/.ssh/config from manifest.")
profile_app = typer.Typer(no_args_is_help=True, help="Manage profiles.")
host_app = typer.Typer(no_args_is_help=True, help="Manage hosts within a profile.")
notify_app = typer.Typer(no_args_is_help=True, help="Expiry notifier (launchd/cron).")
snapshots_app = typer.Typer(no_args_is_help=True, help="Local ~/.ssh backups (list/restore/prune).")
knownhosts_app = typer.Typer(no_args_is_help=True, help="Pin host keys via ssh-keyscan.")
app.add_typer(config_app, name="config")
app.add_typer(profile_app, name="profile")
app.add_typer(host_app, name="host")
app.add_typer(notify_app, name="notify")
app.add_typer(snapshots_app, name="snapshots")
app.add_typer(knownhosts_app, name="knownhosts")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sshmgr {__version__}")
        raise typer.Exit()


@app.callback()
def _banner(
    version: bool = typer.Option(
        False, "--version", help="show the version and exit",
        is_eager=True, callback=_version_callback),
) -> None:
    """Cheap, debounced expiry reminder printed before every command.
    Best-effort + to stderr so it never breaks scripting or a missing manifest."""
    with contextlib.suppress(Exception):
        text = SshManagerService().expiry_banner()
        if text:
            render.console(stderr=True).print(text, style="yellow")


def _service() -> SshManagerService:
    return SshManagerService()


def _fail(exc: SshManagerError) -> typer.Exit:
    typer.secho(str(exc), fg=typer.colors.RED, err=True)
    return typer.Exit(code=1)


def _show_key_configs(svc: SshManagerService, key_names: list[str]) -> None:
    """Display the SSH config options for freshly generated keys."""
    views = svc.config_views_for_keys(key_names)
    if views:
        _console.print("\nGenerated key config options:", style="bold")
        for detail in views:
            _console.print(render.host_detail(detail))
        # Reachable hosts are auto-pinned; remind about unreachable ones + deploy so a
        # first push doesn't fail cryptically.
        _console.print(
            "\nNext: [bold]sshmgr deploy <key>[/bold] (install the public key on the "
            "target). Reachable hosts' keys are auto-pinned; for any VPN-gated host, "
            "connect the VPN and run [bold]sshmgr knownhosts pin --all[/bold].")


def _confirmed(prompt: str, yes: bool) -> bool:
    """A confirmation that `--yes` can skip (for non-interactive/scripted use)."""
    return yes or typer.confirm(prompt)


_YES = typer.Option(False, "--yes", "-y", help="skip confirmation prompts")


def _resolve_passphrase(flag: bool | None) -> str:
    """Passphrases default OFF but are always a conscious choice (invariant 10):
    --passphrase / --no-passphrase script it; otherwise prompt once on a TTY."""
    import sys
    if flag is False:
        return ""
    if flag is None:
        if not sys.stdin.isatty():
            return ""                       # non-interactive default: off
        if not typer.confirm("Protect new keys with a passphrase?", default=False):
            return ""
    return str(typer.prompt("Passphrase", hide_input=True, confirmation_prompt=True))


@app.command()
def version() -> None:
    """Print the ssh-manager version."""
    typer.echo(f"sshmgr {__version__}")


@app.command()
def tui() -> None:
    """Launch the interactive TUI (browse / preview / manage over the Facade)."""
    import sys
    if not sys.stdin.isatty():
        typer.secho("The TUI needs an interactive terminal - use the CLI verbs "
                    "(sshmgr --help) in scripts/pipes.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    from .tui import Tui
    Tui().run()


@app.command()
def recover(
    key: str = typer.Argument(None, help="key to re-add; omit for the full recovery tool"),
) -> None:
    """Print a break-glass recovery script to paste into a provider console."""
    try:
        typer.echo(_service().recovery_script(key))
    except SshManagerError as exc:
        raise _fail(exc) from exc


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="auto-fix perms first"),
    json_: bool = typer.Option(False, "--json", help="machine-readable output (scripting)"),
) -> None:
    """Check dependencies, perms, agent, known_hosts, ≤1-old invariant, drift."""
    svc = _service()
    if fix:
        for change in svc.fix_perms():
            if not json_:
                typer.echo(f"fixed perms: {change}")
    report = svc.doctor()
    if json_:
        import json
        typer.echo(json.dumps(report.as_dict(), indent=2))
    else:
        typer.echo(report.format())
    raise typer.Exit(code=0 if report.ok else 1)


@app.command()
def init(
    force: bool = typer.Option(
        False, "--force", "-f",
        help="overwrite manifest/inventory/providers/.env with fresh defaults"),
    backup: bool = typer.Option(
        False, "--backup",
        help="with --force, copy the old files into <home>/.state/ before overwriting"),
) -> None:
    """Create/converge the per-user home (OS-standard, e.g. ~/.config/ssh-manager):
    (re)create the directory structure + perms every run, seed missing files.
    --force resets the seed files to defaults (no backup unless you add --backup)."""
    try:
        res = _service().init(force=force, backup=backup)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(res.format())


@app.command()
def migrate(
    force: bool = typer.Option(
        False, "--force", "-f",
        help="if both the legacy and standard home exist, back up the current home and replace it"),
) -> None:
    """Migrate a legacy ~/.sshmgr home to the OS-standard location. Auto-migration
    handles the simple case on any command; use this when both exist (a stranded
    legacy home that `doctor` warns about)."""
    try:
        res = _service().migrate_home(force=force)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(res.format())


@app.command("import")
def import_cmd(
    path: str = typer.Argument("~/.ssh/config", help="ssh config to onboard"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force", "-f",
                               help="replace an existing non-empty manifest (backed up first)"),
) -> None:
    """Onboard: parse an existing ~/.ssh into manifest + inventory."""
    try:
        res = _service().import_ssh(Path(path), dry_run=dry_run, force=force)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(res.format())


@app.command()
def reconcile(
    dry_run: bool = typer.Option(False, "--dry-run"),
    passphrase: bool = typer.Option(None, "--passphrase/--no-passphrase",
                                    help="protect newly minted keys (default: off)"),
    no_pin: bool = typer.Option(False, "--no-pin",
                                help="don't auto-pin reachable hosts' known_hosts"),
) -> None:
    """Apply the manifest to ~/.ssh: rebuild config, mint missing keys, fix perms,
    and auto-pin each profile's known_hosts for reachable hosts (--no-pin to skip)."""
    pw = "" if dry_run else _resolve_passphrase(passphrase)
    svc = _service()
    try:
        res = svc.reconcile(dry_run=dry_run, passphrase=pw, auto_pin=not no_pin)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(res.format())
    if res.minted and not res.dry_run:
        _show_key_configs(svc, [m.key_name for m in res.minted])


@app.command()
def diff() -> None:
    """Preview manifest vs. on-disk reality."""
    try:
        typer.echo(_service().diff())
    except SshManagerError as exc:
        raise _fail(exc) from exc


@app.command()
def keygen(
    target: str,
    passphrase: bool = typer.Option(None, "--passphrase/--no-passphrase",
                                    help="protect newly minted keys (default: off)"),
    force: bool = typer.Option(False, "--force", "-f",
                               help="overwrite existing keys (prompts; ~/.ssh snapshotted first)"),
    no_pin: bool = typer.Option(False, "--no-pin",
                                help="don't auto-pin reachable hosts' known_hosts"),
    yes: bool = _YES,
) -> None:
    """Targeted key generation. Missing keys are minted; existing keys are warned
    about and SKIPPED unless --force (which prompts per key, ~/.ssh backed up first).
    The affected profiles' known_hosts are auto-pinned for reachable hosts."""
    svc = _service()
    try:
        existing = svc.existing_keys(target)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    overwrite: set[str] = set()
    if existing:
        typer.secho(f"⚠ {len(existing)} key(s) already exist in {target!r}: "
                    + ", ".join(existing), fg=typer.colors.YELLOW, err=True)
        if not force:
            typer.echo("  existing keys will be SKIPPED - re-run with --force to "
                       "overwrite (a ~/.ssh snapshot is taken first; undo via "
                       "`sshmgr snapshots restore`).")
        else:
            for name in existing:
                if yes or typer.confirm(
                        f"  overwrite {name}? (~/.ssh is snapshotted first)"):
                    overwrite.add(name)
    try:
        minted = svc.keygen(target, passphrase=_resolve_passphrase(passphrase),
                            overwrite=overwrite, auto_pin=not no_pin)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    if not minted:
        typer.echo(f"no keys minted for {target!r} (all present; --force to overwrite)")
        return
    for m in minted:
        typer.echo(f"minted {m.key_name}  {m.fingerprint}  (needs-redeploy)")
    _show_key_configs(svc, [m.key_name for m in minted])


@app.command()
def deploy(
    key: str,
    target: str = typer.Argument(None, help="host alias; all hosts using the key if omitted"),
) -> None:
    """ssh-copy-id / provider adapter + record the deployment."""
    try:
        report = _service().deploy(key, target)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(report.format())
    # Any deploy that was attempted and failed (provider/API error, ssh-copy-id
    # failure, or an unreachable/VPN-gated host) is a non-zero outcome, so scripts
    # can tell the key didn't land. A manual/web-panel target that still needs a
    # paste is NOT an error (error=False) - it exits 0.
    if any(r.error for r in report.records):
        raise typer.Exit(1)


@app.command("list")
def list_cmd(profile: str | None = typer.Option(None, "--profile"),
             provider: str | None = typer.Option(None, "--provider"),
             type_: str | None = typer.Option(None, "--type", help="provider category, e.g. vcs"),
             tag: str | None = typer.Option(None, "--tag")) -> None:
    """Profiles -> hosts -> keys (tree), filterable across profiles."""
    try:
        groups = _service().list_groups(profile=profile, provider=provider, type_=type_, tag=tag)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    if not groups and any((profile, provider, type_, tag)):
        _console.print(render.no_match())
    else:
        _console.print(render.list_tree(groups))


@app.command()
def view(selector: str) -> None:
    """Resolved config + keys + deployments for a profile/host/alias."""
    try:
        detail = _service().view_detail(selector)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    if isinstance(detail, ProfileSummary):
        _console.print(render.profile_summary(detail))
    else:
        _console.print(render.host_detail(detail))


@app.command()
def load(profile: str) -> None:
    """Add a profile's keys to the agent."""
    try:
        added = _service().load(profile)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"loaded {len(added)} key(s) into the agent: {', '.join(added) or '(none)'}")


@app.command()
def rotate(
    key: str,
    allow_unverified: bool = typer.Option(False, "--allow-unverified",
                                          help="commit even if a target can't auto-verify"),
    passphrase: bool = typer.Option(None, "--passphrase/--no-passphrase",
                                    help="protect the rotated-in key (default: off)"),
    yes: bool = _YES,
) -> None:
    """Zero-downtime rotation: stage -> deploy -> verify -> archive old."""
    if not _confirmed(f"Rotate {key}? (~/.ssh is snapshotted first)", yes):
        raise typer.Exit(code=1)
    pw = _resolve_passphrase(passphrase)
    try:
        report = _service().rotate(key, allow_unverified=allow_unverified, passphrase=pw)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(report.format())
    raise typer.Exit(code=0 if report.committed else 1)


@app.command()
def rollback(key: str, yes: bool = _YES) -> None:
    """Restore the single /old/ predecessor (plain reverse move)."""
    if not _confirmed(f"Roll back {key} to its /old/ predecessor?", yes):
        raise typer.Exit(code=1)
    try:
        report = _service().rollback(key)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(report.format())


@app.command()
def expiry() -> None:
    """Keys nearing/over their rotation age."""
    try:
        states = _service().expiry_states()
    except SshManagerError as exc:
        raise _fail(exc) from exc
    _console.print(render.expiry_table(states))


@app.command()
def providers(
    export: bool = typer.Option(
        False, "--export",
        help="write the default catalog to <home>/providers.json to customize"),
    force: bool = typer.Option(False, "--force", help="overwrite an existing file (with --export)"),
) -> None:
    """List configured providers and whether each one's credential is present.
    With --export, materialize the shipped default catalog into the home to edit."""
    svc = _service()
    if export:
        try:
            dest = svc.export_providers(force=force)
        except SshManagerError as exc:
            raise _fail(exc) from exc
        typer.echo(f"wrote provider catalog to {dest} - edit it to customize "
                   "(delete it to track the shipped default again)")
        return
    try:
        infos = svc.list_providers()
    except SshManagerError as exc:
        raise _fail(exc) from exc
    _console.print(render.providers_table(infos))


@app.command()
def net(selector: str | None = typer.Argument(None, help="host alias, profile, or key")) -> None:
    """Network connection status for each host, with a VPN indicator. Hosts marked
    `requires_vpn` show a reminder to connect their VPN when they're unreachable."""
    try:
        rows = _service().network_status(selector)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    _console.print(render.network_table(rows))
    if any(not r.status.reachable and r.status.requires_vpn for r in rows):
        raise typer.Exit(1)


@app.command()
def validate(
    selector: str = typer.Argument(None, help="key name or profile; omit for all keys"),
) -> None:
    """Validate managed keypairs: each key parses, the public matches the private,
    and perms are correct. Exits non-zero if any key fails."""
    try:
        checks = _service().validate_keys(selector)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    _console.print(render.validate_table(checks))
    if any(not c.ok for c in checks):
        raise typer.Exit(code=1)


@app.command()
def audit(notify: bool = typer.Option(False, "--notify")) -> None:
    """Drift / expiry / hygiene report (+ optional desktop alert)."""
    try:
        typer.echo(_service().audit(notify=notify))
    except SshManagerError as exc:
        raise _fail(exc) from exc


@app.command()
def bundle(
    recipient: str = typer.Option(None, "--recipient", "-r",
                                  help="age recipient (else $SSH_MANAGER_AGE_RECIPIENT)"),
    output: str = typer.Option(None, "--output", "-o", help="destination dir (else config-dir)"),
) -> None:
    """Encrypted backup (age)."""
    try:
        result = _service().bundle(
            recipient=recipient, output=Path(output) if output else None
        )
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(result.format())


@app.command()
def restore(
    bundle_path: str = typer.Argument(..., help="path to the .age bundle"),
    identity: str = typer.Option(None, "--identity", "-i",
                                 help="age identity file (else $SSH_MANAGER_AGE_IDENTITY_FILE)"),
    yes: bool = _YES,
) -> None:
    """Restore the same keys from an encrypted bundle."""
    if not _confirmed("Restore ~/.ssh from this bundle? (current tree is snapshotted first)", yes):
        raise typer.Exit(code=1)
    try:
        result = _service().restore(
            Path(bundle_path), identity_file=Path(identity) if identity else None
        )
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(result.format())


@config_app.command("check")
def config_check() -> None:
    """Verify ~/.ssh/config matches the manifest (read-only; exit!=0 on drift)."""
    try:
        res = _service().config_check()
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(res.format())
    raise typer.Exit(code=0 if res.in_sync else 1)


@config_app.command("render")
def config_render(dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    """Re-render config + profiles/*/config from the manifest (config-only)."""
    try:
        res = _service().config_render(dry_run=dry_run)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    verb = "would write" if res.dry_run else "wrote"
    typer.echo(f"{verb}: {', '.join(res.written) or '(nothing)'}")
    if res.pruned:
        typer.echo(f"pruned: {', '.join(res.pruned)}")


@config_app.command("show")
def config_show(alias: str = typer.Argument(None)) -> None:
    """Print the resolved config (or `ssh -G` for one alias)."""
    try:
        typer.echo(_service().config_show(alias))
    except SshManagerError as exc:
        raise _fail(exc) from exc


@profile_app.command("add")
def profile_add(
    name: str,
    shared: bool = typer.Option(False, "--shared", help="key_scope=shared (one key per profile)"),
    key_name: str = typer.Option(None, "--key-name", help="profile key name (shared scope)"),
) -> None:
    """Add a profile."""
    try:
        _service().profile_add(
            name, key_scope="shared" if shared else "per_service", key_name=key_name)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"added profile {name}. Run `sshmgr reconcile` to apply.")


@profile_app.command("edit")
def profile_edit(
    name: str,
    key_scope: str = typer.Option(None, "--key-scope", help="per_service | shared"),
    key_name: str = typer.Option(None, "--key-name"),
) -> None:
    """Edit a profile."""
    try:
        _service().profile_edit(name, key_scope=key_scope, key_name=key_name)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"edited profile {name}. Run `sshmgr reconcile` to apply.")


@profile_app.command("delete")
def profile_delete(
    name: str,
    yes: bool = _YES,
    revoke: bool = typer.Option(False, "--revoke",
                                help="also revoke deployed keys from targets (with --yes)"),
) -> None:
    """Delete a profile (prompts to revoke + prune)."""
    if not _confirmed(f"Delete profile {name!r} and all its hosts?", yes):
        raise typer.Exit(code=1)
    do_revoke = revoke if yes else typer.confirm(
        "Revoke deployed public keys from their targets first?")
    try:
        result = _service().profile_delete(name, revoke=do_revoke)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(result.format())


@host_app.command("add")
def host_add(
    profile: str,
    alias: str,
    hostname: str = typer.Option(..., "--hostname", "-H"),
    user: str = typer.Option(..., "--user", "-u"),
    port: int = typer.Option(22, "--port", "-p"),
    provider: str = typer.Option(None, "--provider"),
    token_env: str = typer.Option(None, "--token-env"),
    key_name: str = typer.Option(None, "--key-name"),
    tag: list[str] = typer.Option(None, "--tag", help="repeatable"),
) -> None:
    """Add a host to a profile."""
    try:
        _service().host_add(
            profile, alias, hostname=hostname, user=user, port=port,
            provider=provider, token_env=token_env, key_name=key_name, tags=tag)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"added host {alias} to {profile}. Run `sshmgr reconcile` to apply.")


@host_app.command("edit")
def host_edit(
    profile: str,
    alias: str,
    hostname: str = typer.Option(None, "--hostname", "-H"),
    user: str = typer.Option(None, "--user", "-u"),
    port: int = typer.Option(None, "--port", "-p"),
    provider: str = typer.Option(None, "--provider"),
    token_env: str = typer.Option(None, "--token-env"),
    key_name: str = typer.Option(None, "--key-name"),
) -> None:
    """Edit a host."""
    try:
        _service().host_edit(
            profile, alias, hostname=hostname, user=user, port=port,
            provider=provider, token_env=token_env, key_name=key_name)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"edited host {alias}. Run `sshmgr reconcile` to apply.")


@host_app.command("delete")
def host_delete(
    profile: str,
    alias: str,
    yes: bool = _YES,
    revoke: bool = typer.Option(False, "--revoke",
                                help="also revoke the deployed key from targets (with --yes)"),
) -> None:
    """Delete a host (prompts to revoke + prune)."""
    if not _confirmed(f"Delete host {alias!r} from {profile!r}?", yes):
        raise typer.Exit(code=1)
    do_revoke = revoke if yes else typer.confirm(
        "Revoke the deployed public key from its targets first?")
    try:
        result = _service().host_delete(profile, alias, revoke=do_revoke)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(result.format())


@notify_app.command("install")
def notify_install() -> None:
    """Install the scheduled expiry notifier."""
    try:
        command = _service().notify_install()
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"installed scheduled notifier: {command}")


@notify_app.command("test")
def notify_test() -> None:
    """Fire a test notification."""
    try:
        sent = _service().notify_test()
    except SshManagerError as exc:
        raise _fail(exc) from exc
    if sent:
        typer.echo("sent a test desktop notification.")
    else:
        typer.secho("no notification backend found (install notify-send / "
                    "terminal-notifier).", fg=typer.colors.YELLOW, err=True)


@snapshots_app.command("list")
def snapshots_list() -> None:
    """List local ~/.ssh snapshots (oldest → newest)."""
    snaps = _service().list_snapshots()
    if not snaps:
        typer.echo("no snapshots yet")
        return
    for s in snaps:
        size = s.stat().st_size
        typer.echo(f"{s.name}\t{size:>8} bytes")


@snapshots_app.command("restore")
def snapshots_restore(
    snapshot_id: str = typer.Argument(None, help="snapshot name/substring; latest if omitted"),
    yes: bool = _YES,
) -> None:
    """Restore ~/.ssh from a snapshot (snapshots the current tree first)."""
    if not _confirmed("Restore ~/.ssh from a snapshot? (current tree is snapshotted first)", yes):
        raise typer.Exit(code=1)
    try:
        chosen = _service().restore_snapshot(snapshot_id)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(f"restored from {chosen.name}")


@snapshots_app.command("prune")
def snapshots_prune(keep: int = typer.Option(10, "--keep", help="how many to retain")) -> None:
    """Prune old snapshots, keeping the most recent N."""
    removed = _service().prune_snapshots(keep)
    typer.echo(f"pruned {removed} snapshot(s)")


@knownhosts_app.command("init")
def knownhosts_init(
    profile: str = typer.Argument(
        None, help="profile to initialize; omit with --all/--user"),
    all_: bool = typer.Option(False, "--all", help="initialize every profile's store"),
    user: bool = typer.Option(False, "--user",
                              help="also initialize the per-user ~/.ssh/known_hosts"),
    force: bool = typer.Option(
        False, "--force",
        help="re-scan already-trusted hosts and add any new keys (won't remove a superseded one)"),
) -> None:
    """Initialize known_hosts and pin reachable hosts (trust-on-first-use;
    fingerprints reported). Scope: a PROFILE, --all profiles, and/or --user (the
    conventional ~/.ssh/known_hosts used for ad-hoc ssh/git). Use `knownhosts pin`
    to review-and-confirm a single host before trusting it."""
    try:
        report = _service().init_known_hosts(
            profile=profile, all_profiles=all_, user=user, force=force)
    except SshManagerError as exc:
        raise _fail(exc) from exc
    typer.echo(report.format())


@knownhosts_app.command("pin")
def knownhosts_pin(
    host: str = typer.Argument(None, help="host to pin; omit with --all for every manifest host"),
    all_: bool = typer.Option(False, "--all", help="pin every host in the manifest"),
    port: int = typer.Option(22, "--port", "-p"),
    yes: bool = typer.Option(False, "--yes", "-y", help="trust scanned keys without prompting"),
) -> None:
    """Seed each host's per-profile known_hosts via ssh-keyscan, with confirmation."""
    svc = _service()
    targets: list[tuple[str | None, str, str, int]] = []
    try:
        if all_:
            targets = list(svc.known_hosts_targets())
        elif host:
            # Resolve the alias to the manifest host's real hostname/port; only a
            # host that isn't in the manifest is scanned verbatim (with the --port).
            match = next((t for t in svc.known_hosts_targets() if t[1] == host), None)
            targets = [match] if match else [(svc.profile_of_alias(host), host, host, port)]
    except SshManagerError as exc:
        raise _fail(exc) from exc
    if not targets:
        typer.secho("give a HOST or use --all", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    # group confirmed keys by profile (each writes to profiles/<p>/known_hosts)
    by_profile: dict[str | None, list[str]] = {}
    for profile, _alias, hostname, pt in targets:
        for sk in svc.known_hosts_scan(hostname, pt):
            typer.echo(f"[{profile or 'global'}] {sk.host}  {sk.keytype}  {sk.fingerprint}")
            if yes or typer.confirm(f"  trust this {sk.keytype} key for {sk.host}?"):
                by_profile.setdefault(profile, []).append(sk.line)
    total = sum(svc.known_hosts_add(lines, prof) for prof, lines in by_profile.items())
    typer.echo(f"pinned {total} host key(s) into per-profile known_hosts")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
