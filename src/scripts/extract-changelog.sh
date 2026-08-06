#!/usr/bin/env bash
#
# Print the CHANGELOG.md section for a given tag, used as the GitHub release body.
#
#   ./scripts/extract-changelog.sh v0.1.0
#
set -euo pipefail

tag="${1:?usage: extract-changelog.sh <tag>}"
version="${tag#v}"
changelog="${CHANGELOG_FILE:-CHANGELOG.md}"

[ -f "$changelog" ] || { echo "error: $changelog not found" >&2; exit 1; }

# Print lines between "## [<version>]" and the next "## [" heading.
awk -v ver="$version" '
  $0 ~ "^## \\[" ver "\\]"  { capture = 1; next }
  capture && /^## \[/       { exit }
  capture && /^\[[^]]+\]:/  { exit }   # stop at link-reference definitions
  capture                   { print }
' "$changelog" | sed -e 's/[[:space:]]*$//' | awk 'NF {p=1} p'
