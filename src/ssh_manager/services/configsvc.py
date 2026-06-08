"""Config render / check / show.

All three modes drive the ONE renderer (invariant 3): ``check`` renders to a
buffer and compares byte-for-byte against disk, so the verifier and the writer
can never disagree. ``check`` changes nothing and exits non-zero on drift.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from ..core.manifest import Manifest
from ..core.renderer import ROOT_CONFIG, compose_root_config, render_all
from ..platforms.base import Platform
from ..util import fs, perms, proc
from ..util.paths import Paths


@dataclass
class ConfigCheckResult:
    file_diffs: dict[str, str] = field(default_factory=dict)   # relpath -> unified diff
    missing: list[str] = field(default_factory=list)            # rendered but absent on disk
    orphan: list[str] = field(default_factory=list)            # managed file on disk, not rendered
    ssh_errors: dict[str, str] = field(default_factory=dict)    # alias -> ssh -G stderr

    @property
    def in_sync(self) -> bool:
        return not (self.file_diffs or self.missing or self.orphan)

    def format(self) -> str:
        if self.in_sync and not self.ssh_errors:
            return "config: in sync with the manifest ✓"
        lines: list[str] = []
        for rel in self.missing:
            lines.append(f"MISSING  {rel} (manifest renders it; not on disk)")
        for rel in self.orphan:
            lines.append(f"ORPHAN   {rel} (managed file on disk; manifest renders none)")
        for rel, diff in self.file_diffs.items():
            lines.append(f"DRIFT    {rel}")
            lines.append(diff)
        for alias, err in self.ssh_errors.items():
            lines.append(f"SSH -G   {alias}: {err}")
        lines.append("config: DRIFT detected - run: sshmgr config render")
        return "\n".join(lines)


@dataclass
class WriteResult:
    written: list[str] = field(default_factory=list)
    pruned: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    dry_run: bool = False


class ConfigService:
    def __init__(self, platform: Platform, paths: Paths, manifest: Manifest) -> None:
        self._platform = platform
        self._paths = paths
        self._manifest = manifest

    def rendered(self) -> dict[str, str]:
        return render_all(
            self._manifest, emit_use_keychain=self._platform.emits_use_keychain
        )

    # the fixer
    def write(self, *, dry_run: bool = False) -> WriteResult:
        rendered = self.rendered()
        res = WriteResult(dry_run=dry_run)
        ssh = self._paths.ssh_dir
        for rel, content in rendered.items():
            dest = ssh / rel
            current = dest.read_text(encoding="utf-8") if dest.exists() else None
            # The root ~/.ssh/config may carry foreign content (e.g. an OrbStack
            # Include); compose preserves it around our managed block. Profile
            # configs live under profiles/ and are fully owned, so written as-is.
            target = compose_root_config(current, content) if rel == ROOT_CONFIG else content
            if current == target:
                res.unchanged.append(rel)
                continue
            res.written.append(rel)
            if not dry_run:
                if rel != ROOT_CONFIG:
                    fs.ensure_dir(dest.parent, perms.DIR_MODE)
                fs.write_text_atomic(dest, target, perms.CONFIG_MODE)
        for rel in self._config_files_on_disk():
            if rel not in rendered:
                res.pruned.append(rel)
                if not dry_run:
                    (ssh / rel).unlink(missing_ok=True)
        return res

    # the verifier
    def check(self, *, validate_ssh: bool = True) -> ConfigCheckResult:
        rendered = self.rendered()
        res = ConfigCheckResult()
        ssh = self._paths.ssh_dir
        for rel, content in rendered.items():
            dest = ssh / rel
            if not dest.exists():
                res.missing.append(rel)
                continue
            current = dest.read_text(encoding="utf-8")
            # Compare against the composed file (managed block in place, foreign
            # content preserved) so a preserved OrbStack preamble isn't flagged as drift.
            target = compose_root_config(current, content) if rel == ROOT_CONFIG else content
            if current != target:
                res.file_diffs[rel] = _udiff(current, target, rel)
        for rel in self._config_files_on_disk():
            if rel not in rendered:
                res.orphan.append(rel)
        if validate_ssh and proc.has("ssh"):
            res.ssh_errors = self._validate_aliases()
        return res

    # show
    def show(self, alias: str | None = None) -> str:
        if alias is None:
            return "\n".join(
                f"# === {rel} ===\n{content}" for rel, content in self.rendered().items()
            )
        cfg = self._paths.ssh_dir / ROOT_CONFIG
        result = proc.run(["ssh", "-G", "-F", str(cfg), alias])
        return result.stdout if result.returncode == 0 else result.stderr

    # helpers
    def _config_files_on_disk(self) -> list[str]:
        """Config files in the tool-owned namespace present under ~/.ssh.

        Enumerated by LOCATION (root ``config`` + ``profiles/*/config``), not by
        header - so an orphan whose managed-marker was stripped is still caught
        (the tool owns these files)."""
        ssh = self._paths.ssh_dir
        found: list[str] = []
        if (ssh / ROOT_CONFIG).exists():
            found.append(ROOT_CONFIG)
        prof_dir = ssh / "profiles"
        if prof_dir.is_dir():
            for cfg in sorted(prof_dir.glob("*/config")):
                # as_posix() keeps forward slashes so these match the rendered keys
                # ("profiles/<p>/config") on Windows too; str() would yield
                # backslashes there and flag every profile config as an orphan.
                found.append(cfg.relative_to(ssh).as_posix())
        return found

    def _validate_aliases(self) -> dict[str, str]:
        cfg = self._paths.ssh_dir / ROOT_CONFIG
        if not cfg.exists():
            return {}
        errors: dict[str, str] = {}
        for rk in self._manifest.iter_resolved():
            r = proc.run(["ssh", "-G", "-F", str(cfg), rk.host.alias])
            if r.returncode != 0:
                errors[rk.host.alias] = r.stderr.strip()
        return errors


def _udiff(current: str, expected: str, rel: str) -> str:
    diff = difflib.unified_diff(
        current.splitlines(keepends=True),
        expected.splitlines(keepends=True),
        fromfile=f"{rel} (on disk)", tofile=f"{rel} (manifest)",
    )
    return "".join(diff)
