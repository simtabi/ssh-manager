package opstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentServesVault(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "none.toml")
	n := 0
	write := func(body string) string {
		n++
		p := filepath.Join(dir, "agent"+string(rune('0'+n))+".toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, vault, cfg string
		want             bool
		why              string
	}{
		{"default vault, no file", "Private", missing, true, ""},
		{"shared vault, no file", "Simtabi", missing, false, "by default"},
		{"empty file overrides the default", "Private", write(""), false, "not listed"},
		{"whole-vault entry", "Simtabi", write("# keys\n[[ssh-keys]]\nvault = \"simtabi\"  # case-insensitive\n"), true, ""},
		{"item-only entry", "Simtabi", write("[[ssh-keys]]\nitem = \"bot\"\nvault = \"Simtabi\"\n"), false, "single items"},
		{"another vault listed", "Simtabi", write("[[ssh-keys]]\nvault = \"Private\"\n"), false, "not listed"},
	}
	for _, c := range cases {
		got, why := AgentServesVault(c.vault, c.cfg)
		if got != c.want || (c.why != "" && !strings.Contains(why, c.why)) {
			t.Errorf("%s: served=%v (%q), want %v containing %q", c.name, got, why, c.want, c.why)
		}
		if !got && !strings.Contains(why, `vault = "`+c.vault+`"`) {
			t.Errorf("%s: the reason should show the entry to add: %q", c.name, why)
		}
	}
}
