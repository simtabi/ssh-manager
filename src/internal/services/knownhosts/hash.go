package knownhosts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the known_hosts hash format is defined as HMAC-SHA1
	"encoding/base64"
	"strings"
)

// OpenSSH stores a hashed host name as |1|<base64 salt>|<base64 HMAC-SHA1(salt,
// name)>. Plaintext entries make known_hosts a readable inventory of every host
// the user reaches, which matters more once the per-profile stores collapse into
// one file.
//
// This is implemented against the standard library rather than by shelling out to
// `ssh-keygen -H`, which rewrites the file in place and leaves the plaintext
// original behind as known_hosts.old - reintroducing the exact leak hashing is
// meant to close, in a file nobody thinks to delete.
const (
	hashMagic = "|1|"
	// saltLen matches the SHA-1 digest size, which is what OpenSSH generates.
	saltLen = 20
)

// hashHost renders token as a hashed host field under the given salt.
func hashHost(token string, salt []byte) string {
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(token))
	return hashMagic + base64.StdEncoding.EncodeToString(salt) +
		"|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// hashHostFresh hashes token under a newly generated salt.
func hashHostFresh(token string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashHost(token, salt), nil
}

// hostFieldMatches reports whether a known_hosts host field covers token.
//
// Both shapes have to be understood: a store can hold plaintext entries the user
// or ssh itself wrote alongside hashed ones this tool writes, and a hashed entry
// names exactly one host, so comma splitting applies only to plaintext.
func hostFieldMatches(field, token string) bool {
	if strings.HasPrefix(field, hashMagic) {
		return hashedFieldMatches(field, token)
	}
	for _, h := range strings.Split(field, ",") {
		if h == token {
			return true
		}
	}
	return false
}

func hashedFieldMatches(field, token string) bool {
	salt, want, ok := parseHashedField(field)
	if !ok {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(token))
	return hmac.Equal(mac.Sum(nil), want)
}

func parseHashedField(field string) (salt, sum []byte, ok bool) {
	parts := strings.SplitN(strings.TrimPrefix(field, hashMagic), "|", 2)
	if len(parts) != 2 {
		return nil, nil, false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) == 0 {
		return nil, nil, false
	}
	sum, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(sum) == 0 {
		return nil, nil, false
	}
	return salt, sum, true
}

// hashable reports whether a host field can be replaced by a hash.
//
// A wildcard pattern must stay in the clear because a hash matches one exact name
// and would silently stop matching anything. Marker lines (@cert-authority,
// @revoked) carry patterns for the same reason, and an already-hashed field is
// left alone rather than double-hashed.
func hashable(marker, field string) bool {
	return marker == "" &&
		!strings.HasPrefix(field, hashMagic) &&
		!strings.ContainsAny(field, "*?!")
}

// sshmgrTag marks a known_hosts line as one this tool wrote, in the trailing
// comment field sshd(8) defines as free text after the key ("marker hostnames
// keytype key comment"). Only tagged lines are ever candidates for pruning; a
// line without this tag - however it got there - is the user's and is left
// alone.
const sshmgrTag = "sshmgr"

// khLine is a parsed known_hosts line. keytype+key identify the host key itself,
// independent of how the host name is written, which is what makes it possible to
// tell "already pinned" from "new" once names are hashed and no longer compare
// as strings.
type khLine struct {
	marker  string
	field   string
	keytype string
	key     string
	comment string
}

func parseKHLine(raw string) (khLine, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return khLine{}, false
	}
	fields := strings.Fields(line)
	var marker string
	if strings.HasPrefix(fields[0], "@") {
		marker, fields = fields[0], fields[1:]
	}
	if len(fields) < 3 {
		return khLine{}, false
	}
	comment := ""
	if len(fields) > 3 {
		comment = strings.Join(fields[3:], " ")
	}
	return khLine{marker: marker, field: fields[0], keytype: fields[1], key: fields[2], comment: comment}, true
}

// tagged reports whether this line carries the sshmgr comment tag.
func (l khLine) tagged() bool {
	for _, w := range strings.Fields(l.comment) {
		if w == sshmgrTag {
			return true
		}
	}
	return false
}

// tokens is the list of host names a line pins. Hashed fields hold exactly one,
// which is why a plaintext "host,ip" pair has to be split into separate lines
// before hashing.
func (l khLine) tokens() []string {
	if strings.HasPrefix(l.field, hashMagic) {
		return []string{l.field}
	}
	return strings.Split(l.field, ",")
}
