// Package authkeys has pure helpers for editing an authorized_keys file, ported
// from src/ssh_manager/core/authorized_keys.py. Keys are matched by their base64
// wire-format body (validated as a real key blob), so a key is deduped/removed
// regardless of comments or options, and junk lines are ignored.
package authkeys

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// KeyTypes are the OpenSSH public-key type tokens (the token before the body).
var KeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// decodedWireType returns the SSH wire-format type string encoded in a base64 key
// body, or "". A real blob starts with a length-prefixed type string; decoding it
// rejects base64-looking junk.
func decodedWireType(body string) string {
	if len(body) < 20 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(blob) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if n == 0 || 4+int(n) > len(blob) {
		return ""
	}
	t := blob[4 : 4+int(n)]
	for _, b := range t {
		if b > 127 { // must be ASCII
			return ""
		}
	}
	return string(t)
}

// splitKeyLine returns (options, keyType, body, comment, ok) for a real key line.
// Blanks, comments, and malformed lines return ok=false. The body must decode to
// a wire-type matching the line's type token.
func splitKeyLine(line string) (options, keyType, body, comment string, ok bool) {
	stripped := strings.TrimSpace(line)
	if stripped == "" || strings.HasPrefix(stripped, "#") {
		return "", "", "", "", false
	}
	tokens := strings.Fields(stripped)
	typeIndex := -1
	for i, t := range tokens {
		if KeyTypes[t] {
			typeIndex = i
			break
		}
	}
	if typeIndex == -1 || typeIndex+1 >= len(tokens) {
		return "", "", "", "", false
	}
	keyType = tokens[typeIndex]
	body = tokens[typeIndex+1]
	if decodedWireType(body) != keyType {
		return "", "", "", "", false
	}
	return strings.Join(tokens[:typeIndex], " "), keyType, body,
		strings.Join(tokens[typeIndex+2:], " "), true
}

// KeyBody returns the base64 body of a key line (its stable identity), or "".
func KeyBody(line string) string {
	_, _, body, _, ok := splitKeyLine(line)
	if !ok {
		return ""
	}
	return body
}

// IsValidPublicKey reports whether the line parses as a real OpenSSH public key.
func IsValidPublicKey(line string) bool {
	_, _, _, _, ok := splitKeyLine(line)
	return ok
}

// SameKey reports whether two lines carry the same key body.
func SameKey(a, b string) bool {
	body := KeyBody(a)
	return body != "" && body == KeyBody(b)
}

func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	// strings.Split leaves a trailing "" after a final newline; Python splitlines
	// does not. Drop a single trailing empty element to match.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// KeyLines returns the real key lines (blanks/comments/junk dropped).
func KeyLines(text string) []string {
	var out []string
	for _, ln := range splitLines(text) {
		if IsValidPublicKey(ln) {
			out = append(out, ln)
		}
	}
	return out
}

// CountKeys returns how many real keys are in the text.
func CountKeys(text string) int { return len(KeyLines(text)) }

// ErrNotAPublicKey is returned by AddKeyToText for a non-key line.
var ErrNotAPublicKey = errors.New("not a valid public key")

// AddKeyToText appends newLine unless its body is already present.
func AddKeyToText(text, newLine string) (out string, added bool, err error) {
	body := KeyBody(newLine)
	if body == "" {
		return text, false, ErrNotAPublicKey
	}
	for _, ln := range splitLines(text) {
		if SameKey(ln, newLine) {
			return text, false, nil
		}
	}
	base := strings.TrimRight(text, "\n")
	prefix := ""
	if base != "" {
		prefix = base + "\n"
	}
	return prefix + strings.TrimSpace(newLine) + "\n", true, nil
}

// RemoveKeyFromText removes every line whose body matches targetLine.
func RemoveKeyFromText(text, targetLine string) (out string, removed int) {
	body := KeyBody(targetLine)
	if body == "" {
		return text, 0
	}
	var kept []string
	for _, line := range splitLines(text) {
		if KeyBody(line) == body {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	joined := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if joined == "" {
		return "", removed
	}
	return joined + "\n", removed
}
