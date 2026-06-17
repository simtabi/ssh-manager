// Package recover emits break-glass recovery material, ported from
// facade.recovery_script + _recovery_snippet. With no key it returns the full
// interactive fixkeys tool; with a key name it returns a self-contained POSIX
// snippet that re-adds that key to authorized_keys.
package recover

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simtabi/ssh-manager/internal/core/authkeys"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// fixkeysScript is the shipped interactive recovery tool, kept byte-identical to
// data/fixkeys.sh (a test enforces it).
//
//go:embed fixkeys.sh
var fixkeysScript []byte

// Script returns the recovery material: the full fixkeys tool when keyName is
// empty, else a per-key re-add snippet. Mirrors facade.recovery_script.
func Script(p paths.Paths, m *manifest.Manifest, keyName string) (string, error) {
	if keyName == "" {
		return string(fixkeysScript), nil
	}
	if m == nil {
		return "", fmt.Errorf("no manifest - run `sshmgr init` first")
	}
	rks, err := m.IterResolved()
	if err != nil {
		return "", err
	}
	pubPath := ""
	for _, rk := range rks {
		if rk.KeyName == keyName {
			pubPath = filepath.Join(p.SSHDir, "profiles", rk.Profile, keyName+".pub")
			break
		}
	}
	if pubPath == "" || !exists(pubPath) {
		return "", fmt.Errorf("public key not found for %q - run `sshmgr reconcile` first", keyName)
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}
	pubtext := strings.TrimSpace(string(b))
	if !authkeys.IsValidPublicKey(pubtext) {
		return "", fmt.Errorf("%s: %s is not a valid public key", keyName, pubPath)
	}
	return snippet(keyName, pubtext), nil
}

// snippet builds the per-key recovery script. The base64 body is computed here
// (not via awk in the script, which breaks for option-prefixed lines), and both
// values are escaped for a POSIX single-quoted literal. Mirrors _recovery_snippet.
func snippet(keyName, pubkey string) string {
	body := authkeys.KeyBody(pubkey)
	safeKey := strings.ReplaceAll(pubkey, "'", "'\\''")
	safeBody := strings.ReplaceAll(body, "'", "'\\''")
	return "#!/bin/sh\n" +
		"# ssh-manager recovery: paste into a locked-out server's console to re-add this key.\n" +
		"# key: " + keyName + "\n" +
		"set -e\n" +
		"KEY='" + safeKey + "'\n" +
		"BODY='" + safeBody + "'\n" +
		"AK=\"$HOME/.ssh/authorized_keys\"\n" +
		"mkdir -p \"$HOME/.ssh\"; chmod 700 \"$HOME/.ssh\"; touch \"$AK\"\n" +
		"cp \"$AK\" \"$AK.ssh-manager.bak\" 2>/dev/null || true\n" +
		"grep -qF \"$BODY\" \"$AK\" || printf '%s\\n' \"$KEY\" >> \"$AK\"\n" +
		"chmod 600 \"$AK\"\n" +
		"echo \"ssh-manager: key in place. Test SSH from another terminal before closing this console.\"\n"
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }
