package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestKeyCommentFor(t *testing.T) {
	prev := keyCommentHostname
	t.Cleanup(func() { keyCommentHostname = prev })
	keyCommentHostname = func() (string, error) { return "Imani's MBP.local", nil }

	m := Starter(false)
	ref := KeyRef{Profile: "work", KeyName: "work_gh-ed25519"}
	m.Profiles["work"] = Profile{KeyScope: "per_service"}
	if got := KeyComment(m, ref, "gh", "2026-10-27"); got != "work/gh 2026-10-27" {
		t.Errorf("default: %q", got)
	}
	m.Defaults.KeyComment = "{key} on {device}"
	if got := KeyComment(m, ref, "gh", "2026-10-27"); got != "work_gh-ed25519 on imani-s-mbp" {
		t.Errorf("defaults.key_comment: %q", got)
	}
	m.Profiles["work"] = Profile{KeyScope: "per_service", KeyComment: "imani-{device}-{date}"}
	if got := KeyComment(m, ref, "gh", "2026-10-27"); got != "imani-imani-s-mbp-2026-10-27" {
		t.Errorf("profile key_comment wins: %q", got)
	}
	keyCommentHostname = func() (string, error) { return "", errors.New("no name") }
	if got := KeyComment(m, ref, "gh", "d"); !strings.Contains(got, "unknown") {
		t.Errorf("an unreadable host name should read unknown: %q", got)
	}
}

func TestCheckKeyComment(t *testing.T) {
	for _, ok := range []string{"", DefaultKeyComment, "imani-{device}-{date}", "plain text"} {
		if err := checkKeyComment("f", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"{user}", "a\nb", "tab\there", "{date", "date}"} {
		if err := checkKeyComment("f", bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}
