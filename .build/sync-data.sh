#!/bin/sh
# Keep the shipped package-data copies in sync with their repo sources, so init
# (on an installed wheel) seeds the same providers catalog / .env template that
# the repo ships. Run by pre-commit on change, by `make sync-data`, and enforced
# by tests/test_packaging.py.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

cp config/providers.json src/ssh_manager/data/providers.json
cp .env-example          src/ssh_manager/data/.env-example
