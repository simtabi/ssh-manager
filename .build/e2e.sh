#!/bin/sh
# e2e.sh - automated end-to-end smoke of the whole ssh-manager flow on macOS.
#
# Runs the tool against a throwaway $HOME + config-dir (never touches your real
# ~/.ssh), generating keys for every profile and exercising every verb, with
# assertions. Exits non-zero on the first failure.
#
# Usage:  .build/e2e.sh              (uses .venv/bin/sshmgr)  |  make -C .build e2e
#         SSHMGR=/path/to/sshmgr .build/e2e.sh
set -eu

# Deterministic + offline: don't auto-pin host keys via ssh-keyscan during
# reconcile (this script exercises explicit `knownhosts pin` separately).
export SSH_MANAGER_AUTO_PIN=0

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSHMGR="${SSHMGR:-$ROOT/.venv/bin/sshmgr}"
[ -x "$SSHMGR" ] || { echo "ssh-manager not found at $SSHMGR (run .build/bootstrap.sh)"; exit 1; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1 -> [$2]"; fi; }

export COLUMNS=200   # keep rich tables/trees from wrapping in narrow CI terminals
SBX="$(mktemp -d)"
trap 'rm -rf "$SBX"' EXIT
export HOME="$SBX/home"; mkdir -p "$HOME"
export SSH_MANAGER_CONFIG_DIR="$SBX/cfg"; mkdir -p "$SSH_MANAGER_CONFIG_DIR"
cp "$ROOT/config/manifest.json" "$SSH_MANAGER_CONFIG_DIR/manifest.json"
SSH="$HOME/.ssh"

echo "==> sandbox: HOME=$HOME  CONFIG=$SSH_MANAGER_CONFIG_DIR"

echo "==> doctor (deps)"
"$SSHMGR" doctor >/dev/null 2>&1 || true   # may be non-zero if config drift; deps matter

echo "==> reconcile --dry-run then reconcile (generate keys for all profiles)"
"$SSHMGR" reconcile --dry-run >/dev/null
"$SSHMGR" reconcile >/dev/null

echo "==> keys minted for every non-empty profile"
for k in work/work_unc-ed25519 \
         personal/personal_github-ed25519 \
         simtabi/simtabi_github-ed25519 \
         development/development_oribi-web-ed25519 \
         development/development_oribi-db-maria-ed25519 \
         development/development_oribi-db-psql-ed25519; do
  check "key $k (priv+pub)" "[ -f '$SSH/profiles/$k' ] && [ -f '$SSH/profiles/$k.pub' ]"
done
check "empty profile 'school' has no dir" "[ ! -d '$SSH/profiles/school' ]"

echo "==> perms are load-bearing"
check "ssh dir is 700"        "[ \"\$(stat -f '%Lp' '$SSH')\" = 700 ]"
check "config 600"            "[ \"\$(stat -f '%Lp' '$SSH/config')\" = 600 ]"
check "private key 600"       "[ \"\$(stat -f '%Lp' '$SSH/profiles/work/work_unc-ed25519')\" = 600 ]"
check "public key 644"        "[ \"\$(stat -f '%Lp' '$SSH/profiles/work/work_unc-ed25519.pub')\" = 644 ]"

echo "==> config check is in sync (exit 0)"
check "config check exit 0"   "\"$SSHMGR\" config check >/dev/null 2>&1"

echo "==> ssh -G resolves the two GitHub identities to DISTINCT keys"
P="$("$SSHMGR" config show github-personal 2>/dev/null | awk '/^identityfile/{print $2}')"
S="$("$SSHMGR" config show github-simtabi 2>/dev/null | awk '/^identityfile/{print $2}')"
check "personal identity"     "echo '$P' | grep -q personal/personal_github-ed25519"
check "simtabi identity"      "echo '$S' | grep -q simtabi/simtabi_github-ed25519"
check "no cross-offer"        "[ '$P' != '$S' ]"

echo "==> idempotency: second reconcile mints nothing, config stays in sync"
OUT="$("$SSHMGR" reconcile 2>&1)"
check "no re-mint"            "echo \"\$OUT\" | grep -q 'all 6 present'"
check "still in sync"         "\"$SSHMGR\" config check >/dev/null 2>&1"

echo "==> drift detection + render fix"
printf '\n# hand edit\n' >> "$SSH/profiles/work/config"
check "drift -> exit !=0"     "! \"$SSHMGR\" config check >/dev/null 2>&1"
"$SSHMGR" config render >/dev/null
check "render fixes drift"    "\"$SSHMGR\" config check >/dev/null 2>&1"

echo "==> list / view / expiry / audit"
check "list --type vcs"       "\"$SSHMGR\" list --type vcs 2>/dev/null | grep -q github-simtabi"
check "list --tag db"         "\"$SSHMGR\" list --tag db 2>/dev/null | grep -q oribi-db-maria"
check "view host"             "\"$SSHMGR\" view unc 2>/dev/null | grep -q 'fingerprint  SHA256:'"
check "expiry all ok"         "\"$SSHMGR\" expiry 2>/dev/null | grep -q ' ok'"
check "audit deployments"     "\"$SSHMGR\" audit 2>/dev/null | grep -q '=== deployments ==='"

echo "==> validate (keypairs) + providers + recover"
WPUB="$SSH/profiles/work/work_unc-ed25519.pub"
check "validate all ok"       "\"$SSHMGR\" validate 2>/dev/null | grep -q 'ok'"
check "validate exit 0"       "\"$SSHMGR\" validate >/dev/null 2>&1"
cp "$WPUB" "$WPUB.e2ebak"; printf 'garbage\n' > "$WPUB"   # break the pub/priv pair
check "validate catches break" "! \"$SSHMGR\" validate work_unc-ed25519 >/dev/null 2>&1"
mv "$WPUB.e2ebak" "$WPUB"                                  # restore the exact original
check "validate ok again"     "\"$SSHMGR\" validate >/dev/null 2>&1"
check "providers listing"     "\"$SSHMGR\" providers 2>/dev/null | grep -q digitalocean"
check "recover snippet"       "\"$SSHMGR\" recover work_unc-ed25519 2>/dev/null | grep -q 'authorized_keys'"

echo "==> keygen: warn-on-existing (skip) + --force overwrite (backup first)"
check "keygen warns existing"  "\"$SSHMGR\" keygen work 2>&1 | grep -qi 'already exist'"
check "keygen skips by default" "\"$SSHMGR\" keygen work 2>&1 | grep -qi 'all present'"
FP_B=$(ssh-keygen -lf "$SSH/profiles/work/work_unc-ed25519" | awk '{print $2}')
"$SSHMGR" keygen work --force --yes >/dev/null 2>&1
FP_A=$(ssh-keygen -lf "$SSH/profiles/work/work_unc-ed25519" | awk '{print $2}')
check "keygen --force regenerates" "[ \"$FP_B\" != \"$FP_A\" ]"
check "overwrite took a snapshot" "\"$SSHMGR\" snapshots list 2>/dev/null | grep -q 'ssh-'"
check "diff present count"     "\"$SSHMGR\" diff 2>/dev/null | grep -q 'key(s) already present'"

echo "==> snapshots: second reconcile snapshotted the tree; restore works"
"$SSHMGR" config render >/dev/null   # a mutating op -> snapshot
check "snapshot exists"       "\"$SSHMGR\" snapshots list 2>/dev/null | grep -q 'ssh-'"
rm "$SSH/profiles/work/work_unc-ed25519"
printf 'y\n' | "$SSHMGR" snapshots restore >/dev/null 2>&1 || true
check "restore recovered key" "[ -f '$SSH/profiles/work/work_unc-ed25519' ]"

echo "==> doctor --fix is clean after a real reconcile"
check "doctor clean"          "\"$SSHMGR\" doctor 2>/dev/null | grep -q 'doctor: clean'"

if command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
  echo "==> bundle + restore: REAL age round-trip"
  age-keygen -o "$SBX/id.txt" >/dev/null 2>&1
  RECIP="$(grep -i 'public key:' "$SBX/id.txt" | sed 's/.*: *//')"
  "$SSHMGR" bundle -r "$RECIP" -o "$SBX" >/dev/null 2>&1
  BUNDLE="$(ls "$SBX"/ssh-manager-*.age 2>/dev/null | head -1)"
  check "age bundle encrypted"  "head -c 21 '$BUNDLE' | grep -q 'age-encryption'"
  rm -f "$SSH/profiles/work/work_unc-ed25519" "$SSH/profiles/work/work_unc-ed25519.pub"
  printf 'y\n' | "$SSHMGR" restore "$BUNDLE" -i "$SBX/id.txt" >/dev/null 2>&1 || true
  check "age restore recovers key" "[ -f '$SSH/profiles/work/work_unc-ed25519' ]"
else
  echo "==> bundle without age -> clear actionable error (age optional)"
  export SSH_MANAGER_AGE_RECIPIENT=age1example
  check "bundle names 'age'"    "\"$SSHMGR\" bundle 2>&1 | grep -qi 'age'"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mE2E PASSED\033[0m: %s checks ok\n' "$PASS"; exit 0
else
  printf '\033[31mE2E FAILED\033[0m: %s ok, %s failed\n' "$PASS" "$FAIL"; exit 1
fi
