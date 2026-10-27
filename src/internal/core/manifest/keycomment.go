package manifest

import (
	"fmt"
	"os"
	"strings"
)

// DefaultKeyComment is the comment sshmgr writes when neither the profile nor
// the defaults set key_comment: the one every release before key_comment wrote.
const DefaultKeyComment = "{profile}/{alias} {date}"

// keyCommentTokens are the placeholders a key_comment template may use.
//
//	{profile}  the profile name
//	{alias}    the first host the key serves, or the key name when none does
//	{key}      the key name (the file under the profile directory)
//	{date}     the day the key is minted, YYYY-MM-DD
//	{device}   this machine's short host name, lowercased
var keyCommentTokens = []string{"{profile}", "{alias}", "{key}", "{date}", "{device}"}

// keyCommentHostname reads the machine name for {device}; tests swap it.
var keyCommentHostname = os.Hostname

// checkKeyComment refuses a template ssh-keygen -C would mangle or sshmgr cannot
// expand: a control character (a newline splits the .pub line), or a brace that
// is not one of keyCommentTokens, which is almost always a typo.
func checkKeyComment(field, tmpl string) error {
	for _, r := range tmpl {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: control characters are not allowed", field)
		}
	}
	rest := tmpl
	for _, tok := range keyCommentTokens {
		rest = strings.ReplaceAll(rest, tok, "")
	}
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("%s %q: unknown placeholder (use %s)", field, tmpl, strings.Join(keyCommentTokens, " "))
	}
	return nil
}

// KeyCommentTemplate resolves the key_comment template for a profile: the
// profile's own, else the defaults', else DefaultKeyComment. It and KeyComment
// are functions, not Manifest methods, to keep that type from regrowing into a
// facade (cmd/sshmgr's layering test caps its method count).
func KeyCommentTemplate(m *Manifest, profile string) string {
	if t := m.Profiles[profile].KeyComment; t != "" {
		return t
	}
	if m.Defaults.KeyComment != "" {
		return m.Defaults.KeyComment
	}
	return DefaultKeyComment
}

// KeyComment expands the profile's key_comment for one key. alias is the
// host the key serves (callers pass the key name for an unwired key) and date
// the mint day.
func KeyComment(m *Manifest, ref KeyRef, alias, date string) string {
	return strings.NewReplacer(
		"{profile}", ref.Profile,
		"{alias}", alias,
		"{key}", ref.KeyName,
		"{date}", date,
		"{device}", device(),
	).Replace(KeyCommentTemplate(m, ref.Profile))
}

// device is the short, lowercased machine name, reduced to characters that are
// safe in a comment: mbp.local -> mbp, "Imani's MacBook" -> imani-s-macbook.
func device() string {
	name, err := keyCommentHostname()
	if err != nil {
		return "unknown"
	}
	name, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(name)), ".")
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
