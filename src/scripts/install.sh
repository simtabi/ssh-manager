#!/usr/bin/env bash
#
# sshmgr installer for macOS and Linux.
#
#   curl -fsSL https://opensource.simtabi.com/install/ssh-manager | bash
#   curl -fsSL https://opensource.simtabi.com/install/ssh-manager | bash -s v0.1.0
#
# Windows users: use scripts/install.ps1 (irm ... | iex) or download the bare
# sshmgr_windows_<arch>.exe from the GitHub releases page.
#
set -euo pipefail

OWNER="simtabi"
REPO="ssh-manager"
BINARY="sshmgr"

# Per-project env-var prefix, derived so it stays a valid shell identifier for
# any project name (uppercase, non-alnum -> '_'): e.g. sshmgr -> "SSHMGR".
PREFIX="$(printf '%s' "$BINARY" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"
dir_var="${PREFIX}_INSTALL_DIR"
INSTALL_DIR="${!dir_var:-/usr/local/bin}"

err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*" >&2; }

[ "$(id -u)" = "0" ] && err "do not run this installer as root; it requests sudo only when needed."

# --- detect os (artifact token: darwin → macos) -----------------------------
case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux)  os="linux" ;;
  *) err "unsupported OS $(uname -s). On Windows, use the PowerShell installer or the .zip from the releases page." ;;
esac

# --- detect arch (Go-style GOARCH, matching the release artifact names) ------
case "$(uname -m)" in
  x86_64|amd64)   arch="amd64" ;;
  arm64|aarch64)  arch="arm64" ;;
  armv7l)         arch="armv7" ;;
  armv6l)         arch="armv6" ;;
  i386|i686)      arch="386" ;;
  *) err "unsupported architecture $(uname -m)." ;;
esac

if [ "$os" = "macos" ] && [ "$arch" != "amd64" ] && [ "$arch" != "arm64" ]; then
  err "unsupported macOS architecture $(uname -m)."
fi

# --- version resolution -----------------------------------------------------
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  api="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  # ${auth[@]+"${auth[@]}"}, not "${auth[@]}": under `set -u`, bash 3.2 treats an
  # EMPTY array expansion as an unbound variable and exits. macOS still ships
  # 3.2.57 as /bin/bash, which is what `#!/usr/bin/env bash` finds there unless
  # the user has installed a newer one - so the documented `curl ... | bash`
  # failed on a stock Mac with "auth[@]: unbound variable", before downloading
  # anything, for everyone who did not happen to have GITHUB_TOKEN set (which
  # made the array non-empty and hid it). Fixed in bash 4.4; this idiom works in
  # both.
  # Fetch first, parse second, rather than piping curl into `grep -m1`. grep -m1
  # closes the pipe as soon as it matches, curl gets EPIPE and exits 56
  # ("Failure writing output to destination"), and `set -o pipefail` turns that
  # into a failed install - intermittently, depending on whether curl had
  # finished writing. awk reads a here-string, so there is no pipeline left for
  # an early exit to break.
  body="$(curl -fsSL ${auth[@]+"${auth[@]}"} -H 'Accept: application/vnd.github+json' "$api")"
  VERSION="$(awk -F'"' '/"tag_name"/{print $4; exit}' <<<"$body")"
fi
[ -n "$VERSION" ] || err "could not determine the version to install."
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac

# Bare, ready-to-run binary (the release tag carries the version).
asset="${BINARY}_${os}_${arch}"
base="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"

sha_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    grep " ${asset}\$" "$1" | sha256sum -c -
  else
    grep " ${asset}\$" "$1" | shasum -a 256 -c -
  fi
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

info "Downloading ${asset} (${VERSION}) ..."
curl -fsSL "${base}/${asset}" -o "${workdir}/${asset}"
if curl -fsSL "${base}/checksums.txt" -o "${workdir}/checksums.txt" 2>/dev/null; then
  ( cd "$workdir" && sha_check checksums.txt ) || err "checksum verification failed for ${asset}"
else
  info "warning: checksums.txt not found; skipping verification."
fi

sudo=""
if [ ! -d "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR" 2>/dev/null || { sudo="sudo"; $sudo mkdir -p "$INSTALL_DIR"; }
fi
if [ -z "$sudo" ] && [ ! -w "$INSTALL_DIR" ]; then
  sudo="sudo"
  info "Requesting sudo to write to ${INSTALL_DIR} ..."
fi
$sudo install -m 0755 "${workdir}/${asset}" "${INSTALL_DIR}/${BINARY}"

# Shell completions (best effort).
if command -v brew >/dev/null 2>&1; then
  prefix="$(brew --prefix)"
  "${INSTALL_DIR}/${BINARY}" completion bash > "${prefix}/etc/bash_completion.d/${BINARY}" 2>/dev/null || true
  "${INSTALL_DIR}/${BINARY}" completion zsh  > "${prefix}/share/zsh/site-functions/_${BINARY}" 2>/dev/null || true
elif [ -d /etc/bash_completion.d ] && [ -w /etc/bash_completion.d ]; then
  "${INSTALL_DIR}/${BINARY}" completion bash > "/etc/bash_completion.d/${BINARY}" 2>/dev/null || true
fi

info ""
"${INSTALL_DIR}/${BINARY}" version || true
info ""
info "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
