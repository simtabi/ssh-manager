package providers

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/authkeys"
)

// removeScript is the remote read-modify-write of authorized_keys, run as one ssh
// command under flock. Exit codes: 0 removed; 2 key not present; 3 lockout guard;
// 4 lock/setup failure. {body} is a single-quote-escaped base64 body. Verbatim
// from ssh_generic._REMOVE_SCRIPT.
const removeScript = `set -eu
AK="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
[ -f "$AK" ] || : > "$AK"
exec 9>"$HOME/.ssh/.ssh-manager.lock" || exit 4
if command -v flock >/dev/null 2>&1; then flock 9 || exit 4; fi
BODY='{body}'
grep -qF -- "$BODY" "$AK" || exit 2
TMP="$(mktemp "$AK.ssh-manager.XXXXXX")" || exit 4
grep -vF -- "$BODY" "$AK" > "$TMP" || true
if ! grep -Eq '^[[:space:]]*[^[:space:]#]' "$TMP"; then rm -f "$TMP"; exit 3; fi
cp -p "$AK" "$AK.ssh-manager.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
chmod 600 "$TMP"
mv "$TMP" "$AK"
`

// GenericSSH is the universal fallback: ssh-copy-id / authorized_keys on any
// reachable server. Ports providers.ssh_generic.GenericSSH.
type GenericSSH struct{ spec Spec }

func (g GenericSSH) Name() string {
	if g.spec.Name != "" {
		return g.spec.Name
	}
	return "generic-ssh"
}

func (g GenericSSH) Category() string {
	if g.spec.Category != "" {
		return g.spec.Category
	}
	return "server"
}

func (g GenericSSH) ManageURL(Target) string  { return g.spec.ResolvedKeysURL() }
func (GenericSSH) Rename(Target, string) bool { return false }

func (g GenericSSH) knownHostsOpts(t Target) []string {
	if t.KnownHosts != "" {
		return []string{"-o", "UserKnownHostsFile=" + t.KnownHosts}
	}
	return nil
}

func (g GenericSSH) sshBase(t Target) []string {
	base := append([]string{"ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"}, g.knownHostsOpts(t)...)
	if t.Port != 22 {
		base = append(base, "-p", strconv.Itoa(t.Port))
	}
	return base
}

func (g GenericSSH) Deploy(t Target) DeployOutcome {
	if _, err := exec.LookPath("ssh-copy-id"); err != nil {
		return g.deployOverSSH(t)
	}
	args := append([]string{"-o", "ConnectTimeout=10"}, g.knownHostsOpts(t)...)
	args = append(args, "-i", t.PubkeyPath)
	if t.Port != 22 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	args = append(args, t.SSHDest())
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-copy-id", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return DeployOutcome{Method: "ssh-copy-id", Detail: "ssh-copy-id failed: " + err.Error(), Error: true}
	}
	return DeployOutcome{Method: "ssh-copy-id", Verified: true, Detail: "authorized_keys updated"}
}

// appendKeyScript is what ssh-copy-id does, as one POSIX sh command: create
// ~/.ssh restrictively, append the key unless it is already there, and leave
// authorized_keys owner-only. The key arrives on stdin rather than in the
// command line, so it stays out of the remote process list.
const appendKeyScript = `umask 077; mkdir -p ~/.ssh || exit 1; ` +
	`touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys || exit 1; ` +
	`k=$(cat); [ -n "$k" ] || exit 1; ` +
	`grep -qxF "$k" ~/.ssh/authorized_keys || printf '%s\n' "$k" >> ~/.ssh/authorized_keys`

// deployOverSSH installs the key with plain ssh, for hosts where ssh-copy-id is
// not available.
//
// Microsoft's OpenSSH port does not ship ssh-copy-id, so on Windows this is the
// normal path rather than a fallback - and refusing to deploy there was the
// reason ssh-copy-id had to be a hard dependency in the first place. ssh-copy-id
// is a shell script around exactly this command, so nothing is given up: same
// modes, same dedupe, same result.
func (g GenericSSH) deployOverSSH(t Target) DeployOutcome {
	if t.PubkeyText == "" {
		return DeployOutcome{Method: "ssh", Detail: "no public key text to install", Error: true}
	}
	args := append(g.sshBase(t), t.SSHDest(), appendKeyScript)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(strings.TrimSpace(t.PubkeyText) + "\n")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return DeployOutcome{Method: "ssh", Error: true,
			Detail: "ssh-copy-id is not installed and the ssh fallback failed: " + err.Error()}
	}
	return DeployOutcome{Method: "ssh", Verified: true, Detail: "authorized_keys updated (via ssh)"}
}

func (g GenericSSH) Verify(t Target) bool {
	if t.IdentityPath == "" {
		return false
	}
	args := append([]string{"ssh", "-i", t.IdentityPath, "-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new"}, g.knownHostsOpts(t)...)
	if t.Port != 22 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	args = append(args, t.SSHDest(), "true")
	return runOK(20*time.Second, args...)
}

func (g GenericSSH) ListDeployed(t Target) []string {
	out := g.readAuthorizedKeys(t)
	return authkeys.KeyLines(out)
}

func (g GenericSSH) Remove(t Target) bool {
	body := authkeys.KeyBody(t.PubkeyText)
	if body == "" {
		return false
	}
	script := strings.ReplaceAll(removeScript, "{body}", strings.ReplaceAll(body, "'", "'\\''"))
	args := append(g.sshBase(t), t.SSHDest(), script)
	return runOK(30*time.Second, args...)
}

func (g GenericSSH) readAuthorizedKeys(t Target) string {
	args := append(g.sshBase(t), t.SSHDest(), "cat ~/.ssh/authorized_keys 2>/dev/null || true")
	out, err := runOutput(20*time.Second, args...)
	if err != nil {
		return ""
	}
	return out
}

func runOK(timeout time.Duration, argv ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run() == nil
}

func runOutput(timeout time.Duration, argv ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	return string(out), err
}
