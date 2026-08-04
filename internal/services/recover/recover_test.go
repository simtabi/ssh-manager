package recover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// fixkeys.sh is now shipped only as the embedded copy - there is no second file
// to drift from - so what is worth pinning is the script's own contract. It runs
// on a server the user is locked out of, edits authorized_keys, and is pasted
// into a provider's recovery console.
//
// Note it deliberately does NOT `set -e`: it is an interactive menu, and
// aborting the whole session because one command returned non-zero is the
// opposite of what a recovery tool should do.
func TestEmbeddedFixkeysKeepsItsContract(t *testing.T) {
	script := string(fixkeysScript)
	checks := []struct {
		want string
		why  string
	}{
		{"#!", "no shebang, so it depends on how it happens to be invoked"},
		{"set -u", "an unset variable in a script that rewrites authorized_keys must not expand to nothing"},
		{"/dev/tty", "prompts must read from the terminal, or pasting the script eats its own menu answers"},
		{"backup()", "it promises every change is backed up first"},
		{"write_atomic()", "a half-written authorized_keys is a lockout"},
	}
	for _, c := range checks {
		if !strings.Contains(script, c.want) {
			t.Errorf("fixkeys.sh is missing %q: %s", c.want, c.why)
		}
	}
	if strings.Contains(script, "rm -rf") {
		t.Error("a permissions repair script has no business deleting a tree")
	}
}

func TestScriptFullTool(t *testing.T) {
	got, err := Script(paths.Paths{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(fixkeysScript) {
		t.Error("no-key recover should return the fixkeys tool verbatim")
	}
}

func TestSnippet(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: base}
	mj := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git","key_name":"k"}]}}}`
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(mj), &m); err != nil {
		t.Fatal(err)
	}
	pubBody := "AAAAC3NzaC1lZDI1NTE5AAAAIKBhbiwvJigPhtwCSedPrebJ6NRC27KYLY3l/okYRnNA"
	pub := "ssh-ed25519 " + pubBody + " a comment\n"
	dir := filepath.Join(p.SSHDir, "profiles", "work")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "k.pub"), []byte(pub), 0o644)

	got, err := Script(p, &m, "k")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# key: k\n",
		"KEY='ssh-ed25519 " + pubBody + " a comment'\n", // comment kept, no trailing newline
		"BODY='" + pubBody + "'\n",
		"printf '%s\\n' \"$KEY\"", // literal backslash-n preserved for the runtime printf
	} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet missing %q\n---\n%s", want, got)
		}
	}

	// Unknown key -> error.
	if _, err := Script(p, &m, "nope"); err == nil {
		t.Error("unknown key should error")
	}
}
