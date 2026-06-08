"""The shipped package data stays in sync with its repo sources.

`init` (on an installed wheel) seeds providers.json / .env from package data; these
must match the repo's `config/providers.json` and `.env-example`. Drift fails here
- run `make sync-data` (pre-commit does it automatically on change)."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("source,shipped", [
    ("config/providers.json", "src/ssh_manager/data/providers.json"),
    (".env-example", "src/ssh_manager/data/.env-example"),
])
def test_package_data_in_sync(source: str, shipped: str) -> None:
    src = (ROOT / source).read_text(encoding="utf-8")
    dst = (ROOT / shipped).read_text(encoding="utf-8")
    assert src == dst, f"{shipped} drifted from {source} - run `make sync-data`"
