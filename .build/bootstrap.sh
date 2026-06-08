#!/bin/sh
# bootstrap.sh - POSIX-sh installer (runs before Python/venv exist).
#
# Usage (lives in .build/, but always operates on the repo root):
#   .build/bootstrap.sh                # install deps + venv + hooks, then fix perms
#   .build/bootstrap.sh --perms-only   # only (re)assert file perms/groups, no install
#   .build/bootstrap.sh --no-perms     # install but skip the perms pass
set -eu

# Run from the repo root regardless of where this script is invoked from.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

# detect OS (informational; the Python platform layer is authoritative)
OS="$(uname -s 2>/dev/null || echo unknown)"

# chmod a path only if it exists and its mode differs (idempotent, quiet).
_fix() {  # _fix <octal-mode> <path>
  _mode="$1"; _path="$2"
  [ -e "$_path" ] || return 0
  _cur="$(_stat_mode "$_path")"
  if [ "$_cur" != "$_mode" ]; then
    chmod "$_mode" "$_path" && printf '  perms %s -> %s\n' "$_path" "$_mode"
  fi
}

# portable `stat` for the octal mode (BSD/macOS vs GNU/Linux).
_stat_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then stat -f '%Lp' "$1"   # BSD/macOS
  else stat -c '%a' "$1"; fi                                       # GNU/Linux
}

# Intelligently fix perms + deny group/other on every sensitive path. SSH refuses
# loose key/config perms, and secrets must never be group/world readable.
fix_perms() {
  say "Fixing perms/groups (OS: $OS)"
  # executable scripts
  for s in .build/bootstrap.sh .build/e2e.sh .build/sync-data.sh .build/feature-check.sh; do
    [ -f "$s" ] && chmod u+x "$s"
  done
  # The per-user home (OS config dir) and ~/.ssh are owned + fixed by the tool itself
  # (it knows the path->mode policy, and creates the home only on `sshmgr init`).
  if [ -x .venv/bin/sshmgr ]; then
    .venv/bin/sshmgr doctor --fix >/dev/null 2>&1 || true
  fi
  # Note on groups: we deliberately do NOT chgrp/chown (that needs root and risks
  # breaking ownership). Denying group/other access (go-rwx) is the safe, correct
  # hardening for a single-user tool; run as the file owner.
  if [ "$(id -u)" = "0" ]; then
    warn "running as root - files will be root-owned; prefer running as your user"
  fi
}

DO_INSTALL=1; DO_PERMS=1
case "${1:-}" in
  --perms-only) DO_INSTALL=0 ;;
  --no-perms)   DO_PERMS=0 ;;
  "" ) ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

if [ "$DO_INSTALL" = "1" ]; then
  say "Detected OS: $OS"

  # Python >= 3.11
  PY="${PYTHON:-python3}"
  if ! command -v "$PY" >/dev/null 2>&1; then
    echo "python3 not found. On macOS: brew install python@3.12" >&2; exit 1
  fi
  "$PY" - <<'PYEOF'
import sys
assert sys.version_info[:2] >= (3, 11), f"Python 3.11+ required, found {sys.version.split()[0]}"
PYEOF

  # virtualenv + editable install
  if [ ! -d .venv ]; then say "Creating .venv"; "$PY" -m venv .venv; fi
  # shellcheck disable=SC1091
  . .venv/bin/activate
  say "Installing ssh-manager (editable) + dev extras"
  python -m pip install --upgrade pip >/dev/null
  python -m pip install -e ".[dev]"

  # pre-commit hooks (best-effort)
  if command -v pre-commit >/dev/null 2>&1; then
    say "Installing pre-commit hooks"; pre-commit install || true
  fi
fi

[ "$DO_PERMS" = "1" ] && fix_perms

if [ "$DO_INSTALL" = "1" ]; then
  say "Done. Try: . .venv/bin/activate && sshmgr init && sshmgr doctor"
fi
