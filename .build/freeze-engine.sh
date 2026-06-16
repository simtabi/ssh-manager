#!/bin/sh
# Freeze the Python engine into a single self-contained executable and place it
# where a `-tags bundled` Go build embeds it (internal/engine/embed/engine).
# PyInstaller cannot cross-compile, so run this on each target OS; CI does it
# per-runner before goreleaser builds that OS's binary.
#
# Usage:  PYTHON=.venv/bin/python .build/freeze-engine.sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PY="${PYTHON:-.venv/bin/python}"
OUT="internal/engine/embed"
mkdir -p "$OUT"

"$PY" -m PyInstaller --onefile --name ssh-manager-engine \
  --paths src \
  --collect-all ssh_manager \
  --collect-all pydantic --collect-all pydantic_core \
  --collect-all typer --collect-all click --collect-all rich \
  --collect-all questionary --collect-all jinja2 --collect-all dotenv \
  --workpath build/engine --distpath build/engine/dist --specpath build/engine \
  src/ssh_manager/__main__.py

BIN="build/engine/dist/ssh-manager-engine"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
cp "$BIN" "$OUT/engine"
echo "engine embedded at $OUT/engine ($(du -h "$OUT/engine" | cut -f1))"
