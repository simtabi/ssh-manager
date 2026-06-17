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

func TestEmbeddedFixkeysMatchesShipped(t *testing.T) {
	shipped, err := os.ReadFile("../../../src/ssh_manager/data/fixkeys.sh")
	if err != nil {
		t.Skip("shipped fixkeys.sh not present")
	}
	if string(shipped) != string(fixkeysScript) {
		t.Error("embedded fixkeys.sh drifted from data/fixkeys.sh")
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
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "k.pub"), []byte(pub), 0o644)

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
