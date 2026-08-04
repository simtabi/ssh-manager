package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/inventory"
	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/keyaudit"
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

// A key nothing will ever use should be noticed by the command that left it
// that way, not days later by doctor.
func TestReconcileWarnsAboutBlockingDanglingKeys(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "key", "add", "work", "work_spare-ed25519") // declared, wired to nothing

	out := run(t, "reconcile")
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, keyaudit.Unwired) {
		t.Errorf("reconcile should warn about the unwired key:\n%s", out)
	}
	if !strings.Contains(out, "key delete work/work_spare-ed25519") {
		t.Errorf("the warning should carry the way out:\n%s", out)
	}

	// Wiring it clears that warning - and strands the key gh used to name, which
	// is reported by the edit itself rather than discovered later.
	edited := run(t, "host", "edit", "work", "gh", "--key-name", "work_spare-ed25519")
	if !strings.Contains(edited, "WARNING") || !strings.Contains(edited, keyaudit.Untracked) {
		t.Errorf("re-pointing a host should report the key it stranded:\n%s", edited)
	}
	if !strings.Contains(edited, "work_gh-ed25519") {
		t.Errorf("the stranded key should be named:\n%s", edited)
	}
	out = run(t, "reconcile")
	if strings.Contains(out, keyaudit.Unwired) {
		t.Errorf("the newly wired key should no longer be unwired:\n%s", out)
	}
}

// An unminted key is the normal state between `host add` and reconcile, so it
// must not shout - it warns only in doctor, and fails only under --strict.
func TestReconcileDoesNotWarnAboutAnUnmintedKey(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	out := run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	if strings.Contains(out, "WARNING") {
		t.Errorf("adding a host should not warn about the key it has yet to mint:\n%s", out)
	}
}

// clean removes the one dangling state that is only a JSON record, and says
// plainly that it is leaving the rest - a dangling key surviving a command
// called "clean" without a word is how it stays dangling.
func TestCleanDropsStaleRecordsAndNamesWhatItLeaves(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "reconcile")

	inv, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	inv.Record("SHA256:ghost", inventory.KeyRecord{
		Profile: "gone", Path: "~/.ssh/profiles/gone/gone_key-ed25519", Type: "ed25519",
	})
	if err := inv.Save(p.Inventory()); err != nil {
		t.Fatal(err)
	}
	// And an untracked key file, which clean must report but never delete.
	stray := filepath.Join(p.SSHDir, "profiles", "ghost", "ghost_key-ed25519")
	if err := os.MkdirAll(filepath.Dir(stray), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dry := run(t, "clean", "--dry-run")
	if !strings.Contains(dry, "would drop") || !strings.Contains(dry, "SHA256:ghost") {
		t.Errorf("--dry-run should name the record it would drop:\n%s", dry)
	}
	after, err := inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Keys["SHA256:ghost"]; !ok {
		t.Error("--dry-run dropped the record for real")
	}

	out := run(t, "clean")
	if !strings.Contains(out, "dropped 1 stale inventory record") {
		t.Errorf("clean should drop the stale record:\n%s", out)
	}
	after, err = inventory.Load(p.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Keys["SHA256:ghost"]; ok {
		t.Error("the stale record survived clean")
	}
	if len(after.Keys) == 0 {
		t.Error("clean removed a live record too")
	}
	if !strings.Contains(out, "left alone") || !strings.Contains(out, keyaudit.Untracked) {
		t.Errorf("clean should say what it is not touching:\n%s", out)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("clean deleted a key file: %v", err)
	}
}
