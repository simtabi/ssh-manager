package cli

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/internal/core/expiry"
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
	// Both, not just HOME: paths.home() reads USERPROFILE on Windows, so setting
	// HOME alone left every one of these tests resolving ~/.ssh to the developer's
	// real home - reconciling, rendering and minting keys into it.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_MANAGER_HOME", cfg)
	// Snapshots and auto-pin both reach for the network/filesystem otherwise.
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	// snapshotBeforeMutation takes the advisory lock once per PROCESS and holds
	// it deliberately, because a CLI command exits and the OS releases it. A test
	// binary does not exit between tests, so the lock file stays open - and
	// Windows refuses to delete an open file, which fails t.TempDir's cleanup.
	// Release it per test instead; the next mutating call re-acquires.
	t.Cleanup(func() {
		if heldLock != nil {
			heldLock()
			heldLock = nil
		}
	})
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

// Every other selector in the tool accepts a key; keygen - the one command whose
// whole purpose is a single key - rejected one as an unknown target.
func TestKeygenAcceptsAKeySelector(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "reconcile")

	for _, selector := range []string{"work_gh-ed25519", "work/work_gh-ed25519"} {
		out := run(t, "keygen", selector)
		if strings.Contains(out, "unknown") {
			t.Errorf("keygen rejected %q: %s", selector, out)
		}
		if !strings.Contains(out, "no keys minted") {
			t.Errorf("keygen %q should have found the existing key: %s", selector, out)
		}
	}
}

// A bare key name is only unique inside a profile, so a table of bare names
// showed two rows with one label and no way to tell which was due.
func TestExpiryTableNamesKeysByProfile(t *testing.T) {
	var out bytes.Buffer
	writeExpiryTable(&out, []expiry.Status{
		{KeyName: "imani_github-ed25519", Profile: "personal", State: expiry.OK},
		{KeyName: "imani_github-ed25519", Profile: "adelsaiq", State: expiry.OK},
	})
	got := out.String()
	for _, want := range []string{"personal/imani_github-ed25519", "adelsaiq/imani_github-ed25519"} {
		if !strings.Contains(got, want) {
			t.Errorf("expiry table missing %q:\n%s", want, got)
		}
	}
}

// --- the remaining verbs, driven through Execute -------------------------
//
// Parity reference: python-final:src/ssh_manager/cli.py:221-229 (diff),
// :275-293 (deploy), :401-413 (net). These three had no test at any level; the
// harness above is what makes them reachable, since a command that called
// os.Exit would have taken the test binary with it.

// runErr is run() for a command expected to fail, returning output and error.
func runErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

// diff is read-only: it reports what reconcile would do and changes nothing.
func TestDiffReportsDriftWithoutTouchingAnything(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	// The key is not minted yet, so diff should say it would be.
	out := run(t, "diff")
	if !strings.Contains(out, "MINT") || !strings.Contains(out, "work/work_gh-ed25519") {
		t.Errorf("diff should name the key it would mint:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")); err == nil {
		t.Error("diff must not mint anything")
	}

	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return
	}
	run(t, "reconcile")
	out = run(t, "diff")
	if strings.Contains(out, "MINT") {
		t.Errorf("nothing should be pending after a reconcile:\n%s", out)
	}
	if !strings.Contains(out, "in sync") {
		t.Errorf("diff should report the config as in sync:\n%s", out)
	}
}

// A key used by several hosts is one line, not one per host. It was counted per
// host before, so a shared key read as several outstanding mints.
func TestDiffCountsAKeyOnceNotOncePerHost(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "team", "--shared", "--key-name", "team_all-ed25519")
	run(t, "host", "add", "team", "a", "-H", "a.example", "-u", "x")
	run(t, "host", "add", "team", "b", "-H", "b.example", "-u", "x")

	out := run(t, "diff")
	if n := strings.Count(out, "team_all-ed25519"); n != 1 {
		t.Errorf("the shared key appears %d times, want 1:\n%s", n, out)
	}
}

// net probes every host and reports each one.
func TestNetReportsEveryHost(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	// A closed loopback port refuses instantly rather than timing out.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	run(t, "host", "add", "work", "box", "-H", "127.0.0.1", "-u", "x", "-p", strconv.Itoa(port))

	out := run(t, "net")
	if !strings.Contains(out, "box") {
		t.Errorf("net should list the host:\n%s", out)
	}
	// Selector narrows it.
	if out := run(t, "net", "box"); !strings.Contains(out, "box") {
		t.Errorf("net <alias> should report that host:\n%s", out)
	}
}

// A VPN-gated host that is down is the one case net fails on: it means the
// tunnel is not up, which a script wrapping this needs to act on. An ordinary
// unreachable host is reported but does not fail the command.
func TestNetFailsOnlyWhenAGatedHostIsDown(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "work")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	run(t, "host", "add", "work", "box", "-H", "127.0.0.1", "-u", "x", "-p", strconv.Itoa(port))

	// Not gated: down is reported, but the command succeeds.
	if _, err := runErr(t, "net"); err != nil {
		t.Errorf("an ordinary unreachable host should not fail the command: %v", err)
	}

	// Mark it VPN-gated by editing the manifest directly - `host add` has no
	// flag for it, which is itself worth knowing.
	body, err := os.ReadFile(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	gated := strings.Replace(string(body), `"requires_vpn": false`, `"requires_vpn": true`, 1)
	if gated == string(body) {
		t.Skip("manifest shape changed; requires_vpn not found")
	}
	if err := os.WriteFile(p.Manifest(), []byte(gated), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runErr(t, "net"); err == nil {
		t.Error("a gated host that is down should fail the command")
	}
}

// deploy needs a minted key; without one it names the command that fixes it
// rather than failing on a bare stat.
func TestDeployRefusesAnUnmintedKey(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	out, err := runErr(t, "deploy", "work_gh-ed25519")
	if err == nil {
		t.Fatalf("deploying an unminted key should fail:\n%s", out)
	}
	if !strings.Contains(err.Error(), "reconcile") {
		t.Errorf("the error should point at reconcile: %v", err)
	}
}

// An unknown key selector is an error from every verb that takes one, and the
// message names what was not found.
func TestVerbsRejectUnknownSelectors(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")

	for _, args := range [][]string{
		{"deploy", "no-such-key"},
		{"view", "no-such-thing"},
		{"show", "no-such-thing"},
		{"key", "list", "no-such-thing"},
	} {
		_, err := runErr(t, args...)
		if err == nil {
			t.Errorf("%v should have failed on an unknown selector", args)
			continue
		}
		if !strings.Contains(err.Error(), "no-such") {
			t.Errorf("%v: the error should name what was not found: %v", args, err)
		}
	}
}
