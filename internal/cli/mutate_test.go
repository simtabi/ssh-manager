package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// editHome sets up a real home for a command to run against: $HOME for ~/.ssh
// and $SSH_MANAGER_HOME for the config, both under t.TempDir(), with a starter
// manifest already in place.
func editHome(t *testing.T) paths.Paths {
	t.Helper()
	home := t.TempDir()
	cfg := filepath.Join(home, "cfg")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_MANAGER_HOME", cfg)
	// Snapshots and auto-pin both reach for the network/filesystem otherwise.
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	p := paths.Paths{SSHDir: filepath.Join(home, ".ssh"), ConfigDir: cfg}
	if err := manifest.Starter(false).Save(p.Manifest()); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

func configText(t *testing.T, p paths.Paths) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	return string(b)
}

// The invariant: a command that changes the manifest leaves ~/.ssh/config
// matching it. Before, every edit verb printed "run sshmgr reconcile to apply"
// and left the file stale, so the tool finished by creating exactly the drift
// that `diff` and `doctor` then reported.
func TestManifestEditsRenderTheConfig(t *testing.T) {
	p := editHome(t)

	run(t, "profile", "add", "work")
	// A profile with no hosts renders no Host block, but the managed file exists.
	if txt := configText(t, p); !strings.Contains(txt, "Host *") {
		t.Errorf("expected a managed config after profile add:\n%s", txt)
	}

	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	txt := configText(t, p)
	for _, want := range []string{"Host gh", "HostName github.com", "IdentityFile ~/.ssh/profiles/work/work_gh-ed25519"} {
		t.Run("host add renders "+want, func(t *testing.T) {
			if !strings.Contains(txt, want) {
				t.Errorf("missing %q:\n%s", want, txt)
			}
		})
	}

	run(t, "host", "edit", "work", "gh", "-H", "gitlab.com")
	if txt := configText(t, p); !strings.Contains(txt, "HostName gitlab.com") {
		t.Errorf("an edit should reach the config:\n%s", txt)
	}

	out := run(t, "host", "delete", "work", "gh", "-y")
	if txt := configText(t, p); strings.Contains(txt, "Host gh\n") {
		t.Errorf("a deleted host should leave the config:\n%s", txt)
	}
	if !strings.Contains(out, "re-rendered") {
		t.Errorf("the delete should report the re-render: %s", out)
	}
}

// key add is the case that made the inconsistency obvious: it wires a host to a
// new key, so the IdentityFile the config renders has to change with it.
func TestKeyAddWiresTheConfigNotJustTheManifest(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "key", "add", "work", "work_second-ed25519", "--host", "gh")

	txt := configText(t, p)
	if !strings.Contains(txt, "IdentityFile ~/.ssh/profiles/work/work_second-ed25519") {
		t.Errorf("the wired key should be the rendered IdentityFile:\n%s", txt)
	}
	if strings.Contains(txt, "work_gh-ed25519") {
		t.Errorf("the old derived key should no longer be referenced:\n%s", txt)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "work_second-ed25519")); err != nil {
		t.Errorf("key add should have minted the key: %v", err)
	}
}

// Rendering must never eat config the user wrote themselves - it replaces the
// managed block and leaves everything around it alone.
func TestRenderingPreservesForeignConfig(t *testing.T) {
	p := editHome(t)
	if err := os.MkdirAll(p.SSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const foreign = "Host orbstack\n    HostName 198.19.249.2\n    User imani\n"
	if err := os.WriteFile(filepath.Join(p.SSHDir, "config"), []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	txt := configText(t, p)
	if !strings.Contains(txt, "Host orbstack") || !strings.Contains(txt, "198.19.249.2") {
		t.Errorf("hand-written config was lost:\n%s", txt)
	}
	if !strings.Contains(txt, "Host gh") {
		t.Errorf("the managed block should have been added alongside it:\n%s", txt)
	}
}

// An edit that changes no Host block writes nothing and says nothing, so the
// invariant does not turn every command into noise.
func TestRenderIsQuietWhenNothingChanges(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	before, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	out := run(t, "profile", "edit", "work", "--key-scope", "per_service")
	if strings.Contains(out, "re-rendered") {
		t.Errorf("an edit that changes nothing should not claim a re-render: %s", out)
	}
	after, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the config changed for an edit that changed nothing")
	}
}
