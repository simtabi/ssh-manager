// Package secrets resolves provider tokens, ported from util/secrets.py. A token
// value of cmd:<command> runs the command at use-time and uses its trimmed stdout
// as the secret (so it integrates with any secret manager); anything else is
// returned as-is. Results are memoized per process.
package secrets

import (
	"os/exec"
	"strings"
	"sync"
)

const cmdPrefix = "cmd:"

var cache sync.Map // command -> resolved secret ("" == failure/empty)

// Resolve returns the secret for a token value: cmd:<command> runs the command
// (memoized), anything else is returned unchanged; "" stays "".
func Resolve(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, cmdPrefix) {
		return raw
	}
	command := raw[len(cmdPrefix):]
	if v, ok := cache.Load(command); ok {
		return v.(string)
	}
	out := runCmdSecret(command)
	cache.Store(command, out)
	return out
}

func runCmdSecret(command string) string {
	argv := shlexSplit(command)
	if len(argv) == 0 {
		return ""
	}
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// shlexSplit is a minimal POSIX shell-word splitter (handles single/double quotes
// and backslash escapes) - enough for cmd: secret commands. Mirrors shlex.split.
func shlexSplit(s string) []string {
	var args []string
	var cur strings.Builder
	inWord := false
	quote := byte(0) // 0, '\'', or '"'
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if quote == '"' && c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		args = append(args, cur.String())
	}
	return args
}
