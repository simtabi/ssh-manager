package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bundle no longer carries the rendered config, so restore must re-render it.
// When it cannot (the restored manifest fails to load), restore has to say so:
// before, the error was dropped and ~/.ssh was left without its category files.
func TestFinishRestoreReportsAConfigItCouldNotRender(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "web", "--category", "orgs")
	run(t, "host", "add", "web", "a", "-H", "192.0.2.1", "-u", "u")
	if err := finishRestore(p); err != nil {
		t.Fatalf("a valid manifest did not re-render: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "orgs", "config")); err != nil {
		t.Fatalf("the category config was not rendered: %v", err)
	}
	if err := os.WriteFile(p.Manifest(), []byte(`{"version":1,"profiles":{"web":{"hosts":[{"alias":"a","hostname":"h;x","user":"u"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := finishRestore(p)
	if err == nil || !strings.Contains(err.Error(), "config render") {
		t.Errorf("an unrenderable manifest was not reported: %v", err)
	}
}
