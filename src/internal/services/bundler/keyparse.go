package bundler

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"strings"
)

// looksLikeKey reports whether data is an SSH private or public key, the only
// thing restore lays down in a rendered slot. It parses rather than matching a
// prefix: a file that merely starts with "ssh-" (a config whose first line was
// forged to look like a key) is not one.
func looksLikeKey(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(s, "-----BEGIN ") {
		return isPrivateKey([]byte(s))
	}
	return isPublicKeyLine(s)
}

// isPublicKeyLine accepts exactly one "<type> <base64> [comment]" line whose
// blob is an SSH wire-format key of that type (RFC 4253 section 6.6: the blob
// opens with the key type as a string).
func isPublicKeyLine(s string) bool {
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	typ, rest, ok := readString(blob)
	return ok && string(typ) == fields[0] && len(rest) > 0
}

// opensshMagic opens the payload of an "OPENSSH PRIVATE KEY" block
// (PROTOCOL.key in the OpenSSH source).
const opensshMagic = "openssh-key-v1\x00"

// isPrivateKey accepts one PEM private key block and nothing after it. An
// OpenSSH key is checked through its header to the public key, which is stored
// in clear even when the key has a passphrase; the older PEM forms go through
// the standard library's parsers, or are accepted on their encryption header.
func isPrivateKey(data []byte) bool {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return isOpenSSHKey(block.Bytes)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
		if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
		if block.Type == "RSA PRIVATE KEY" {
			_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			return err == nil
		}
		if block.Type == "EC PRIVATE KEY" {
			_, err := x509.ParseECPrivateKey(block.Bytes)
			return err == nil
		}
		return len(block.Bytes) > 0
	case "PRIVATE KEY":
		_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return err == nil
	case "ENCRYPTED PRIVATE KEY":
		return len(block.Bytes) > 0
	}
	return false
}

func isOpenSSHKey(b []byte) bool {
	rest, ok := bytes.CutPrefix(b, []byte(opensshMagic))
	if !ok {
		return false
	}
	for range 3 { // ciphername, kdfname, kdfoptions
		if _, rest, ok = readString(rest); !ok {
			return false
		}
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) < 1 {
		return false
	}
	pub, _, ok := readString(rest[4:])
	if !ok {
		return false
	}
	typ, keyRest, ok := readString(pub)
	return ok && len(typ) > 0 && len(keyRest) > 0
}

// readString reads one SSH wire string: a big-endian uint32 length and that
// many bytes.
func readString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
