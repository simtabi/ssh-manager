#!/usr/bin/env bash
#
# ssh-manager fixkeys - recover authorized_keys from a provider web/recovery console.
#
# Use this when you're locked out of SSH and the only way in is the provider's
# console (DigitalOcean Recovery Console, GCP serial/browser SSH, Hetzner, ...).
# It runs ON the server, edits authorized_keys directly, and needs no working
# SSH and no Python.
#
# The trick that makes it paste-able: every prompt reads from /dev/tty, not
# stdin - so pasting the whole script doesn't eat the menu answers.
#
# It can list keys (with fingerprints), add a key, remove a key, fix
# permissions, and diagnose why key login fails. Every change is backed up
# first and written atomically.  (Refactored from a standalone VPS key tool.)
set -u

if [ -r /dev/tty ]; then TTY=/dev/tty; else TTY=/dev/stdin; fi
say()  { printf '%s\n' "$*" >"$TTY"; }
ask()  { local p="$1" d="${2:-}" r; [ -n "$d" ] && printf '%s [%s]: ' "$p" "$d" >"$TTY" || printf '%s: ' "$p" >"$TTY"; IFS= read -r r <"$TTY" || r=""; printf '%s' "${r:-$d}"; }
confirm() { local r; printf '%s (y/N): ' "$1" >"$TTY"; IFS= read -r r <"$TTY" || r=""; case "$r" in y|Y|yes) return 0;; *) return 1;; esac; }

pick_user() {
  local def; def="${SUDO_USER:-$(id -un)}"
  AK_USER="$(ask "Which user's authorized_keys to manage" "$def")"
  AK_HOME="$(eval echo "~$AK_USER" 2>/dev/null)"; [ -d "$AK_HOME" ] || AK_HOME="/home/$AK_USER"
  AK_DIR="$AK_HOME/.ssh"; AK_FILE="$AK_DIR/authorized_keys"
}
ensure_file() {
  mkdir -p "$AK_DIR"; chmod 700 "$AK_DIR"; touch "$AK_FILE"; chmod 600 "$AK_FILE"
  if id "$AK_USER" >/dev/null 2>&1; then
    chown -R "$AK_USER":"$(id -gn "$AK_USER" 2>/dev/null || echo "$AK_USER")" "$AK_DIR" 2>/dev/null || true
  fi
}
body_of() { awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/){if(i+1<=NF) print $(i+1); exit}}' <<<"$1"; }
label_of() { awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/){if(i+2<=NF){s="";for(j=i+2;j<=NF;j++)s=s (j>i+2?" ":"") $j;print s}else print $i;exit}}' <<<"$1"; }
fp_of() { command -v ssh-keygen >/dev/null 2>&1 || { printf '(no ssh-keygen)'; return; }; local t o; t="$(mktemp)"; printf '%s\n' "$1" >"$t"; o="$(ssh-keygen -lf "$t" 2>/dev/null)"; rm -f "$t"; printf '%s' "${o:-(unreadable)}"; }
backup() { local d="$AK_FILE.bak.$(date +%Y%m%d-%H%M%S)"; cp -p "$AK_FILE" "$d" && say "  backup: $d"; }
write_atomic() { local t="$AK_FILE.new.$$"; cat >"$t"; chmod 600 "$t"; mv "$t" "$AK_FILE"; id "$AK_USER" >/dev/null 2>&1 && chown "$AK_USER":"$(id -gn "$AK_USER" 2>/dev/null || echo "$AK_USER")" "$AK_FILE" 2>/dev/null || true; }
real_keys() { awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/){print;break}}' "$AK_FILE"; }

list_keys() {
  [ -s "$AK_FILE" ] || { say "  no keys in $AK_FILE"; return 1; }
  local n=0 line; say ""
  while IFS= read -r line; do case "$line" in ''|\#*) continue;; esac; [ -z "$(body_of "$line")" ] && continue; n=$((n+1)); say "  $n. $(label_of "$line")  ($(fp_of "$line"))"; done <"$AK_FILE"
  [ "$n" -gt 0 ] || { say "  no keys"; return 1; }
}
nth_key() { local want="$1" n=0 line; while IFS= read -r line; do case "$line" in ''|\#*) continue;; esac; [ -z "$(body_of "$line")" ] && continue; n=$((n+1)); [ "$n" -eq "$want" ] && { printf '%s' "$line"; return 0; }; done <"$AK_FILE"; return 1; }

add_key() {
  say ""; say "Paste the PUBLIC key line (ssh-ed25519 ...), then Enter:"; local k b
  IFS= read -r k <"$TTY" || k=""; k="$(printf '%s' "$k" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$k" ] && { say "  nothing pasted."; return; }
  b="$(body_of "$k")"; [ -z "$b" ] && { say "  not a valid public key."; return; }
  say "  fingerprint: $(fp_of "$k")"
  grep -qF -- "$b" "$AK_FILE" 2>/dev/null && { say "  already present."; return; }
  confirm "  add this key?" || { say "  cancelled."; return; }
  backup; { cat "$AK_FILE"; printf '%s\n' "$k"; } | write_atomic; say "  added."
}
remove_key() {
  list_keys || return; local c t b rem cnt
  c="$(ask "Number to REMOVE (0 cancels)" "0")"; case "$c" in ''|0) say "  cancelled."; return;; *[!0-9]*) say "  not a number."; return;; esac
  t="$(nth_key "$c")" || { say "  no such number."; return; }; b="$(body_of "$t")"
  say "  selected: $(label_of "$t")  ($(fp_of "$t"))"
  rem="$(awk -v drop="$b" '{keep=1;for(i=1;i<=NF;i++) if($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/){if(i+1<=NF && $(i+1)==drop)keep=0;break} if(keep)print}' "$AK_FILE")"
  cnt="$(printf '%s\n' "$rem" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/){print;break}}' | grep -c .)"
  [ "$cnt" -eq 0 ] && { say "  WARNING: that's the last key - you may lose key login."; confirm "  really leave it empty?" || { say "  aborted. Good call."; return; }; }
  confirm "  remove this key?" || { say "  cancelled."; return; }
  backup; printf '%s\n' "$rem" | write_atomic; say "  removed. $cnt key(s) remain."
}
diagnose() {
  say ""; say "Diagnosis for $AK_USER ($AK_HOME):"
  [ -d "$AK_DIR" ] && say "  .ssh perms:            $(stat -c '%a %U:%G' "$AK_DIR" 2>/dev/null) (want 700 / $AK_USER)" || say "  .ssh dir: MISSING"
  [ -f "$AK_FILE" ] && { say "  authorized_keys perms: $(stat -c '%a %U:%G' "$AK_FILE" 2>/dev/null) (want 600 / $AK_USER)"; say "  key count:             $(real_keys | grep -c .)"; } || say "  authorized_keys: MISSING"
  say "  home perms:            $(stat -c '%a' "$AK_HOME" 2>/dev/null) (must NOT be group/other writable)"
  local s=/etc/ssh/sshd_config
  [ -r "$s" ] && { say "  PubkeyAuthentication:  $(grep -iE '^[[:space:]]*PubkeyAuthentication' "$s" | tail -1 || echo '(default yes)')"; say "  PasswordAuthentication:$(grep -iE '^[[:space:]]*PasswordAuthentication' "$s" | tail -1 || echo '(default varies)')"; } || say "  (can't read $s)"
  say ""; say "If perms look wrong use 'fix permissions'. If sshd blocks you, edit $s and: systemctl restart ssh"
}

say "=== ssh-manager fixkeys: authorized_keys recovery ==="
[ "$(id -u)" -ne 0 ] && say "Note: not root - you can only manage your own user."
pick_user; ensure_file
while true; do
  say ""; say "--- $AK_FILE ---"
  say "  1. list keys"; say "  2. add a key"; say "  3. remove a key"; say "  4. fix permissions"; say "  5. diagnose login"; say "  6. quit"
  case "$(ask "choose" "1")" in
    1) list_keys || true;; 2) add_key;; 3) remove_key;; 4) ensure_file; say "  perms/ownership fixed.";; 5) diagnose;;
    6|q|Q) say ""; say "Done. Before closing this console, open another terminal and confirm SSH works."; break;;
    *) say "  not a valid choice.";;
  esac
done
