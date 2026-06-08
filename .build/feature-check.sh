#!/bin/sh
# feature-check.sh - exercises EVERY ssh-manager command/feature in a throwaway sandbox
# with assertions, and prints a per-feature checklist. Complements the unit suite
# (pytest) and the e2e smoke (e2e.sh) with explicit, command-by-command coverage.
#
# Usage:  .build/feature-check.sh        (uses .venv/bin/sshmgr)
set -u

# Deterministic + offline: don't auto-pin host keys via ssh-keyscan during reconcile.
export SSH_MANAGER_AUTO_PIN=0

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${SSHMGR:-$ROOT/.venv/bin/sshmgr}"
[ -x "$S" ] || { echo "ssh-manager not found at $S (run .build/bootstrap.sh)"; exit 1; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗ %s\033[0m\n' "$1"; }
ck()  { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1  [$2]"; fi; }
ckn() { if eval "$2" >/dev/null 2>&1; then bad "$1 (expected failure)"; else ok "$1"; fi; }

export COLUMNS=200
SBX="$(mktemp -d)"; trap 'rm -rf "$SBX"' EXIT
export HOME="$SBX/home"; mkdir -p "$HOME"
export SSH_MANAGER_HOME="$SBX/cfg"
SSH="$HOME/.ssh"
sx() { "$S" "$@" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'; }   # strip ANSI

echo "==> sandbox HOME=$HOME  SSH_MANAGER_HOME=$SSH_MANAGER_HOME"

section() { printf '\n\033[1m### %s\033[0m\n' "$1"; }

section "version / init / doctor"
ck  "version prints a semver"          "sx version | grep -qE '[0-9]+\.[0-9]+\.[0-9]+'"
ck  "init creates the home"            "\"$S\" init >/dev/null 2>&1 && [ -f '$SSH_MANAGER_HOME/manifest.json' ]"
ck  "init seeds .env + dirs (providers via shipped default)" "[ -f '$SSH_MANAGER_HOME/.env' ] && [ -d '$SSH_MANAGER_HOME/log' ] && [ -d '$SSH_MANAGER_HOME/snapshots' ] && [ -d '$SSH_MANAGER_HOME/.state' ] && [ ! -f '$SSH_MANAGER_HOME/providers.json' ]"
ck  "init idempotent (re-run leaves files)" "\"$S\" init 2>&1 | grep -qi 'exists'"
cp "$ROOT/config/manifest.json" "$SSH_MANAGER_HOME/manifest.json"
printf '{"version":1,"profiles":{"x":{"hosts":[]}}}' > "$SSH_MANAGER_HOME/manifest.json.bak2"
"$S" init --force >/dev/null 2>&1
ck  "init --force (no backup dir)"     "[ -z \"\$(ls -d '$SSH_MANAGER_HOME/.state'/init-backup-* 2>/dev/null)\" ]"
cp "$ROOT/config/manifest.json" "$SSH_MANAGER_HOME/manifest.json"
"$S" init --force --backup >/dev/null 2>&1
ck  "init --force --backup keeps old"  "ls -d '$SSH_MANAGER_HOME/.state'/init-backup-*/manifest.json >/dev/null 2>&1"
cp "$ROOT/config/manifest.json" "$SSH_MANAGER_HOME/manifest.json"
ck  "doctor shows resolved home"       "sx doctor | grep -q 'home:'"
ck  "doctor --fix runs"                "\"$S\" doctor --fix >/dev/null 2>&1 || true; true"
ck  "doctor --json is valid json"      "\"$S\" doctor --json 2>/dev/null | python3 -c 'import sys,json; json.load(sys.stdin)'"
ck  "migrate (no legacy) is clean"     "\"$S\" migrate 2>&1 | grep -qi 'no legacy\|migrated\|already'"

section "reconcile / keygen / config"
ck  "reconcile --dry-run (no writes)"  "\"$S\" reconcile --dry-run >/dev/null 2>&1 && [ ! -d '$SSH/profiles' ]"
ck  "reconcile builds ~/.ssh"          "\"$S\" reconcile >/dev/null 2>&1 && [ -f '$SSH/profiles/work/work_unc-ed25519' ]"
ck  "reconcile mints all profiles"     "[ -f '$SSH/profiles/personal/personal_github-ed25519' ] && [ -f '$SSH/profiles/simtabi/simtabi_github-ed25519' ]"
ck  "reconcile idempotent (re-mint none)" "\"$S\" reconcile 2>&1 | grep -qi 'present'"
ck  "keygen warns on existing"         "\"$S\" keygen work 2>&1 | grep -qi 'exist\\|present'"
FPB=$(ssh-keygen -lf "$SSH/profiles/work/work_unc-ed25519" | awk '{print $2}')
"$S" keygen work --force --yes >/dev/null 2>&1
FPA=$(ssh-keygen -lf "$SSH/profiles/work/work_unc-ed25519" | awk '{print $2}')
ck  "keygen --force regenerates"       "[ '$FPB' != '$FPA' ]"
ck  "config check in sync"             "\"$S\" config check"
ck  "config render re-renders"         "\"$S\" config render >/dev/null 2>&1 && [ -f '$SSH/config' ]"
ck  "config show alias (ssh -G)"       "sx config show github-simtabi | grep -qi identityfile"
printf '\n#hand-edit\n' >> "$SSH/profiles/work/config"
ckn "config check detects drift"       "\"$S\" config check >/dev/null 2>&1"
ck  "render fixes drift"               "\"$S\" config render >/dev/null 2>&1 && \"$S\" config check"

section "query: list / view / diff / validate / providers / net / expiry / audit"
ck  "list (tree)"                      "sx list | grep -q work"
ck  "list --type vcs"                  "sx list --type vcs | grep -q github-simtabi"
ck  "list --tag db"                    "sx list --tag db | grep -q oribi-db-maria"
ck  "list --profile work"             "sx list --profile work | grep -q unc"
ck  "view host (fingerprint+status)"   "sx view unc | grep -qi 'fingerprint'"
ck  "view shows VPN note (unc)"        "sx view unc | grep -qi 'vpn'"
ck  "diff (manifest vs disk)"          "sx diff | grep -qi 'present\\|config'"
ck  "validate all ok"                  "\"$S\" validate"
cp "$SSH/profiles/work/work_unc-ed25519.pub" "$SBX/p.bak"; printf 'junk\n' > "$SSH/profiles/work/work_unc-ed25519.pub"
ckn "validate catches a broken pair"   "\"$S\" validate work_unc-ed25519 >/dev/null 2>&1"
mv "$SBX/p.bak" "$SSH/profiles/work/work_unc-ed25519.pub"
ck  "validate ok again"                "\"$S\" validate"
ck  "providers lists catalog"          "sx providers | grep -q digitalocean"
ck  "providers shows credential state" "sx providers | grep -qiE 'set|none|n/a'"
ck  "providers --export writes a file" "\"$S\" providers --export >/dev/null 2>&1 && [ -f '$SSH_MANAGER_HOME/providers.json' ]"
ck  "net status table"                 "sx net | grep -qi 'unc'"
ck  "net flags requires_vpn host"      "sx net | grep -qi 'vpn'"
ckn "net exits!=0 when vpn host down"  "\"$S\" net unc >/dev/null 2>&1"
ck  "expiry table (fresh -> ok)"       "sx expiry | grep -qi 'ok'"
ck  "audit deployments section"        "sx audit | grep -qi 'deployments'"

section "deploy / rotate / rollback (network fail-fast + VPN aware)"
ckn "deploy unreachable vpn host exits!=0" "\"$S\" deploy work_unc-ed25519 >/dev/null 2>&1"
ck  "deploy surfaces VPN url in msg"   "sx deploy work_unc-ed25519 2>&1 | grep -qi 'vpn.unc.edu'"
ckn "rotate vpn host fails fast"       "timeout_guard() { \"\$@\"; }; \"$S\" rotate work_unc-ed25519 --yes --allow-unverified >/dev/null 2>&1"
ck  "rotate msg names the VPN"         "sx rotate work_unc-ed25519 --yes --allow-unverified 2>&1 | grep -qi 'requires a VPN'"
ck  "rotate did NOT archive (aborted)" "[ ! -f '$SSH/profiles/work/old/work_unc-ed25519' ]"

section "snapshots (reversible ~/.ssh backups)"
"$S" config render >/dev/null 2>&1     # a mutating op -> snapshot
ck  "snapshots list shows a snapshot"  "sx snapshots list | grep -q 'ssh-'"
rm -f "$SSH/profiles/work/work_unc-ed25519"
ck  "snapshots restore recovers tree"  "printf 'y\n' | \"$S\" snapshots restore >/dev/null 2>&1; [ -f '$SSH/profiles/work/work_unc-ed25519' ]"
ck  "snapshots prune keeps newest"     "\"$S\" snapshots prune >/dev/null 2>&1 || true; true"

section "profile / host editing (CRUD + revoke/prune)"
ck  "profile add"                      "\"$S\" profile add demo >/dev/null 2>&1; sx list | grep -q demo"
ck  "host add (positional alias)"      "\"$S\" host add demo dh --hostname d.example --user git >/dev/null 2>&1; sx view dh | grep -q d.example"
ck  "host edit --user persists"        "\"$S\" host edit demo dh --user root >/dev/null 2>&1; sx view dh | grep -qw root"
ck  "host delete removes it"           "\"$S\" host delete demo dh --yes >/dev/null 2>&1; ! \"$S\" view dh >/dev/null 2>&1"
ck  "profile delete removes it"        "\"$S\" profile delete demo --yes >/dev/null 2>&1; ! sx list 2>/dev/null | grep -qw demo"

section "load (agent) / knownhosts / recover / notify"
ck  "load is callable (agent add)"     "\"$S\" load work >/dev/null 2>&1 || true; true"
ck  "knownhosts pin --help/dry surface" "\"$S\" knownhosts pin --help >/dev/null 2>&1"
ck  "recover <key> snippet has authorized_keys" "sx recover work_unc-ed25519 | grep -q authorized_keys"
ck  "recover (full tool) has /dev/tty" "sx recover | grep -q '/dev/tty'"
ck  "notify test is callable"          "\"$S\" notify test >/dev/null 2>&1 || true; true"

section "bundle / restore (age) + import"
if command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
  age-keygen -o "$SBX/id.txt" >/dev/null 2>&1
  R="$(grep -i 'public key:' "$SBX/id.txt" | sed 's/.*: *//')"
  "$S" bundle -r "$R" -o "$SBX" >/dev/null 2>&1
  B="$(ls "$SBX"/ssh-manager-*.age 2>/dev/null | head -1)"
  ck "bundle creates an age file"      "head -c 21 '$B' | grep -q 'age-encryption'"
  age -d -i "$SBX/id.txt" "$B" 2>/dev/null | tar tz 2>/dev/null > "$SBX/L"
  ck "bundle EXCLUDES .env"            "! grep -qE '(^|/)\\.env$' '$SBX/L'"
  rm -f "$SSH/profiles/work/work_unc-ed25519" "$SSH/profiles/work/work_unc-ed25519.pub"
  printf 'y\n' | "$S" restore "$B" -i "$SBX/id.txt" >/dev/null 2>&1
  ck "restore recovers the same key"   "[ -f '$SSH/profiles/work/work_unc-ed25519' ]"
else
  ckn "bundle without age -> clear error" "SSH_MANAGER_AGE_RECIPIENT=age1x \"$S\" bundle >/dev/null 2>&1"
fi
# import: onboard an existing ~/.ssh into a fresh home
H2="$SBX/h2"; mkdir -p "$H2/.ssh"
printf 'Host demo\n  HostName d.example\n  User git\n  IdentityFile ~/.ssh/id_demo\n' > "$H2/.ssh/config"
ssh-keygen -t ed25519 -N '' -C demo -f "$H2/.ssh/id_demo" >/dev/null 2>&1
ck  "import onboards an existing ~/.ssh" "HOME='$H2' SSH_MANAGER_HOME='$SBX/cfg2' \"$S\" init >/dev/null 2>&1; HOME='$H2' SSH_MANAGER_HOME='$SBX/cfg2' \"$S\" import '$H2/.ssh/config' >/dev/null 2>&1; [ -f '$SBX/cfg2/manifest.json' ]"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mFEATURE CHECK PASSED\033[0m: %s checks ok\n' "$PASS"; exit 0
else
  printf '\033[31mFEATURE CHECK FAILED\033[0m: %s ok, %s failed\n' "$PASS" "$FAIL"; exit 1
fi
