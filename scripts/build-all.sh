#!/usr/bin/env bash
#
# Hand-rolled cross-compile build (GoReleaser is the canonical release path).
# Regenerates build/targets.txt from an embedded matrix and produces, under
# build/dist/:
#
#   sshmgr_{os}_{arch}[.exe]        flat, versionless, ready-to-run binaries
#   sshmgr_macos_universal          Intel + Apple Silicon fat binary (on macOS)
#   checksums.txt                   SHA-256 over the bare binaries (bare names)
#   archives/sshmgr_{os}_{arch}.{tar.gz,zip}   binary + LICENSE/README/CHANGELOG
#   archives/checksums.txt          SHA-256 over the archives
#
# Naming: darwin -> macos, arm -> armvN, .exe on windows. Static
# (CGO_ENABLED=0), reproducible (-trimpath), stripped (-s -w), with version
# metadata embedded.
#
# The whole build/ folder is DELETED and REGENERATED on every run — its files
# (targets.txt and all outputs) are rewritten from scratch, so nothing stale
# from a removed/renamed target or a previous run ever survives.
#
#   VERSION=v1.2.3 ./scripts/build-all.sh          # normal
#   ARCHIVES=0 ./scripts/build-all.sh              # binaries only, skip archives
#   TARGETS=path/to/list ./scripts/build-all.sh    # use an external target list
#
# Portable to bash 3.2 (the macOS system bash): no mapfile / wait -n / assoc arrays.
set -euo pipefail

cd "$(dirname "$0")/.."

BINARY="sshmgr"
PKG="github.com/simtabi/ssh-manager/internal/version"
BUILD_DIR="build"
OUT="${BUILD_DIR}/dist"
ARCHIVE_DIR="${OUT}/archives"
TARGETS_FILE="${BUILD_DIR}/targets.txt"
WITH_ARCHIVES="${ARCHIVES:-1}"

# The canonical target matrix. Regenerated into build/targets.txt each run; used
# as the fallback when no targets.txt (or --TARGETS override) is present.
DEFAULT_TARGETS='# Release targets for scripts/build-all.sh — "GOOS GOARCH [GOARM]".
# Regenerated on every build. GoReleaser (.goreleaser.yaml) is the canonical
# release path; this drives the hand-rolled fallback. Names use {os}_{arch} with
# darwin → macos, arm → armvN, and .exe on windows; a macos_universal (Intel +
# Apple Silicon) fat binary is produced on macOS.
linux amd64
linux 386
linux arm64
linux arm 6
linux arm 7
darwin amd64
darwin arm64
windows amd64
windows 386
windows arm64'

# --- preflight ---------------------------------------------------------------
command -v go >/dev/null 2>&1 || { echo "error: 'go' is not on PATH" >&2; exit 1; }

# Capture the effective target matrix BEFORE wiping build/, in priority order:
# an explicit TARGETS override, then the existing build/targets.txt, then the
# embedded default. It is regenerated back into build/targets.txt below.
if [ -n "${TARGETS:-}" ] && [ -f "$TARGETS" ]; then
  MATRIX="$(cat "$TARGETS")"
elif [ -f "$TARGETS_FILE" ]; then
  MATRIX="$(cat "$TARGETS_FILE")"
else
  MATRIX="$DEFAULT_TARGETS"
fi

# Portable SHA-256: Linux ships sha256sum, macOS/BSD ship shasum.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$@"
  else echo "error: no sha256sum or shasum found" >&2; return 1; fi
}

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X ${PKG}.Version=${VERSION} -X ${PKG}.Commit=${COMMIT} -X ${PKG}.Date=${DATE}"

# Extra files bundled into each archive (whichever exist).
EXTRAS=""
for f in LICENSE README.md CHANGELOG.md; do
  [ -f "$f" ] && EXTRAS="${EXTRAS} ${f}"
done

# --- fresh build folder ------------------------------------------------------
echo "==> ${BINARY} ${VERSION} (${COMMIT}) — regenerating ${BUILD_DIR}/"
case "$BUILD_DIR" in ''|/|.|..) echo "error: unsafe BUILD_DIR='$BUILD_DIR'" >&2; exit 1 ;; esac
rm -rf "$BUILD_DIR"
mkdir -p "$OUT"
[ "$WITH_ARCHIVES" = "1" ] && mkdir -p "$ARCHIVE_DIR"
printf '%s\n' "$MATRIX" > "$TARGETS_FILE"   # regenerate the target list
echo "==> regenerated ${TARGETS_FILE}"

# make_archive <bare-binary-filename> <goos>
make_archive() {
  [ "$WITH_ARCHIVES" = "1" ] || return 0
  bin="$1"; goos="$2"
  base="${bin%.exe}"                      # sshmgr_macos_arm64
  stage="$(mktemp -d)"
  cp "${OUT}/${bin}" "${stage}/${bin}"
  # shellcheck disable=SC2086
  [ -n "$EXTRAS" ] && cp $EXTRAS "${stage}/"
  if [ "$goos" = "windows" ]; then
    if command -v zip >/dev/null 2>&1; then
      ( cd "$stage" && zip -qr "${base}.zip" . )
      mv "${stage}/${base}.zip" "${ARCHIVE_DIR}/"
    else
      echo "  ! 'zip' not found — skipping ${base}.zip" >&2
    fi
  else
    tar -czf "${ARCHIVE_DIR}/${base}.tar.gz" -C "$stage" .
  fi
  rm -rf "$stage"
}

# --- build every target ------------------------------------------------------
count=0
have_macos_amd64=0
have_macos_arm64=0

# `|| [ -n "$goos" ]` processes a final line with no trailing newline; the \r in
# IFS tolerates CRLF line endings.
while IFS=$' \t\r' read -r goos goarch goarm || [ -n "${goos:-}" ]; do
  case "$goos" in ''|\#*) continue ;; esac   # skip blanks and comments

  os_token="$goos";   [ "$goos" = "darwin" ] && os_token="macos"
  arch_token="$goarch"; [ "$goarch" = "arm" ] && arch_token="armv${goarm}"
  ext="";             [ "$goos" = "windows" ] && ext=".exe"

  name="${BINARY}_${os_token}_${arch_token}${ext}"
  printf '  -> %-32s' "$name"

  GOOS="$goos" GOARCH="$goarch" GOARM="${goarm:-}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" -o "${OUT}/${name}" ./cmd/sshmgr
  echo "ok"

  make_archive "$name" "$goos"
  count=$((count + 1))
  [ "$name" = "${BINARY}_macos_amd64" ] && have_macos_amd64=1
  [ "$name" = "${BINARY}_macos_arm64" ] && have_macos_arm64=1
done < "$TARGETS_FILE"

[ "$count" -gt 0 ] || { echo "error: no targets built (empty matrix?)" >&2; exit 1; }

# --- macOS universal (Intel + Apple Silicon in one binary) -------------------
if [ "$have_macos_amd64" = 1 ] && [ "$have_macos_arm64" = 1 ]; then
  if command -v lipo >/dev/null 2>&1; then
    uni="${BINARY}_macos_universal"
    printf '  -> %-32s' "$uni"
    lipo -create -output "${OUT}/${uni}" \
      "${OUT}/${BINARY}_macos_amd64" "${OUT}/${BINARY}_macos_arm64"
    echo "ok"
    make_archive "$uni" "darwin"
  else
    echo "  ! 'lipo' not available (non-macOS host) — skipping macos_universal" >&2
  fi
fi

# --- checksums (bare names so install scripts / self-update can look up) ------
( cd "$OUT" && sha256 ${BINARY}_* > checksums.txt )
echo "==> wrote ${OUT}/checksums.txt"
if [ "$WITH_ARCHIVES" = "1" ] && ls "${ARCHIVE_DIR}/${BINARY}_"* >/dev/null 2>&1; then
  ( cd "$ARCHIVE_DIR" && sha256 ${BINARY}_* > checksums.txt )
  echo "==> wrote ${ARCHIVE_DIR}/checksums.txt"
fi

echo "==> done: ${count} binaries in ${OUT}$( [ "$WITH_ARCHIVES" = "1" ] && echo ", archives in ${ARCHIVE_DIR}" )"
