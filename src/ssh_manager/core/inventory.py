"""Inventory domain models. Keyed by SHA256 fingerprint.

The inventory is the deployment-tracking join that turns rotation into a
checklist. It is version-stamped and persisted atomically (invariant 11).
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..util import jsonstore
from ..util.errors import ManifestError

SCHEMA_VERSION = 1


class Deployment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    method: str                 # ssh-copy-id | web-panel | manual | <adapter>
    date: str | None = None
    verified: bool = False      # False == needs-redeploy


class KeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str
    path: str
    type: str = "ed25519"
    comment: str | None = None
    created: str | None = None
    rotate_after_days: int = 365
    expires_on: str | None = None     # derived cache of created + rotate_after_days
    deployments: list[Deployment] = Field(default_factory=list)

    @property
    def needs_redeploy(self) -> bool:
        """True when no deployment is verified (e.g. a freshly minted key)."""
        return not any(d.verified for d in self.deployments)


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = SCHEMA_VERSION
    keys: dict[str, KeyRecord] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            data = jsonstore.read_json(path)
        except ValueError as exc:
            raise ManifestError(f"inventory is not valid JSON: {path}: {exc}") from exc
        except OSError as exc:
            raise ManifestError(f"inventory could not be read: {path}: {exc}") from exc
        try:
            return cls.model_validate(data)
        except Exception as exc:   # pydantic ValidationError -> our typed error
            raise ManifestError(f"inventory failed validation: {path}: {exc}") from exc

    def save(self, path: str | Path) -> None:
        jsonstore.write_json_atomic(path, self.model_dump(mode="json"))

    def record(self, fingerprint: str, rec: KeyRecord) -> None:
        self.keys[fingerprint] = rec


def is_archived_path(path: str) -> bool:
    """True if ``path`` is a rotation's ``/old/`` predecessor slot, i.e.
    ``~/.ssh/profiles/<profile>/old/<key_name>``. Uses the path *structure* (the
    'old' dir sits directly under a profile dir that sits under 'profiles') rather
    than a bare ``"/old/"`` substring, so a profile literally named ``old`` -
    whose active keys live at ``profiles/old/<name>`` - is NOT mistaken for an
    archived key and dropped from expiry/audit."""
    parts = path.split("/")
    # [..., 'profiles', '<profile>', 'old', '<key_name>']
    return len(parts) >= 4 and parts[-2] == "old" and parts[-4] == "profiles"


def compute_expiry(created: str, rotate_after_days: int) -> str:
    """``created`` (YYYY-MM-DD) + rotate_after_days → expires_on (YYYY-MM-DD)."""
    base = datetime.strptime(created, "%Y-%m-%d").date()
    return (base + timedelta(days=rotate_after_days)).isoformat()


def today() -> str:
    return date.today().isoformat()
