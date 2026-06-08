"""Typed errors so the CLI/TUI can fail fast and clear."""
from __future__ import annotations


class SshManagerError(Exception):
    """Base for all ssh-manager errors. Carries a human-actionable message."""


class DependencyError(SshManagerError):
    """A required external binary is missing. Names the install command."""

    def __init__(self, binary: str, install_hint: str) -> None:
        super().__init__(f"missing dependency: {binary!r} - {install_hint}")
        self.binary = binary
        self.install_hint = install_hint


class ManifestError(SshManagerError):
    """The manifest is missing, malformed, or fails validation."""


class DriftError(SshManagerError):
    """On-disk config drifted from what the manifest renders."""


class ProcError(SshManagerError):
    """A shelled-out command exited non-zero."""
