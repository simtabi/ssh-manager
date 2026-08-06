package importer

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/util/paths"
)

func find(hosts []*ParsedHost, alias string) *ParsedHost {
	for _, h := range hosts {
		if h.Alias == alias {
			return h
		}
	}
	return nil
}

func TestParseSSHConfig(t *testing.T) {
	cfg := `# a comment
Host gh
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    ProxyCommand /bin/danger
    ServerAliveInterval 60
Host db web
    HostName 10.0.0.9
    Port 2200
    IdentityFile ~/.ssh/profiles/work/work_db-ed25519
Host *
    Compression yes
Match host foo
    User nobody
`
	hosts := parseSSHConfig(cfg, "", map[string]bool{})

	// Wildcard "*" is skipped; gh, db, web remain (3).
	if len(hosts) != 3 {
		t.Fatalf("parsed %d hosts want 3 (wildcard skipped): %v", len(hosts), hosts)
	}
	gh := find(hosts, "gh")
	if gh == nil || gh.Hostname != "github.com" || gh.User != "git" || gh.Port != 22 {
		t.Fatalf("gh = %+v", gh)
	}
	if gh.IdentityFile != "~/.ssh/id_ed25519" || gh.Profile != "imported" {
		t.Errorf("gh identity/profile = %q / %q", gh.IdentityFile, gh.Profile)
	}
	// ProxyCommand dropped (dangerous); ServerAliveInterval carried as a raw option.
	if len(gh.Extra) != 1 || gh.Extra[0].Key != "serveraliveinterval" || gh.Extra[0].Val != "60" {
		t.Errorf("gh extra = %+v (ProxyCommand should be dropped)", gh.Extra)
	}
	// Multi-alias "Host db web": both get the block's options + the profiles/ profile.
	db, web := find(hosts, "db"), find(hosts, "web")
	if db == nil || web == nil || db.Port != 2200 || web.Port != 2200 {
		t.Fatalf("db/web = %+v / %+v", db, web)
	}
	if db.Profile != "work" || web.Profile != "work" {
		t.Errorf("profile from IdentityFile = %q / %q want work", db.Profile, web.Profile)
	}
}

func TestInferProviderAndProfileFromIdentity(t *testing.T) {
	if p := inferProvider("github.com"); p == nil || *p != "github" {
		t.Errorf("github.com -> %v want github", p)
	}
	if p := inferProvider("GitLab.com"); p == nil || *p != "gitlab" {
		t.Errorf("case-insensitive gitlab failed: %v", p)
	}
	if p := inferProvider("example.com"); p != nil {
		t.Errorf("unknown host should infer no provider, got %v", *p)
	}
	if got := profileFromIdentity("~/.ssh/profiles/simtabi/k"); got != "simtabi" {
		t.Errorf("profileFromIdentity = %q want simtabi", got)
	}
	if got := profileFromIdentity("~/.ssh/id_ed25519"); got != "imported" {
		t.Errorf("profileFromIdentity = %q want imported", got)
	}
}

// An ssh config written on Windows says `~\.ssh\id_ed25519`. Honouring only
// "~/" left that as a literal path starting with a tilde, which then failed to
// glob - so the key was silently skipped and the host imported with no identity.
func TestExpanduserAcceptsBothSeparators(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	cases := map[string]string{
		"~":                    home,
		"~/.ssh/id_ed25519":    filepath.Join(home, ".ssh", "id_ed25519"),
		`~\.ssh\id_ed25519`:    filepath.Join(home, ".ssh", "id_ed25519"),
		"/etc/ssh/ssh_config":  "/etc/ssh/ssh_config",
		"~notauser/.ssh/thing": "~notauser/.ssh/thing", // another user's ~ is not ours to expand
	}
	for in, want := range cases {
		if got := expanduser(in); got != want {
			t.Errorf("expanduser(%q) = %q, want %q", in, got, want)
		}
	}
}

// setupImport builds a config home + a fake ~/.ssh and writes an ssh config into
// it. The importer reads the config from an explicit path, so nothing here
// touches the real home directory.
func setupImport(t *testing.T, config string) (*Importer, paths.Paths, string) {
	t.Helper()
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	cfgPath := filepath.Join(ssh, "config")
	if err := os.WriteFile(cfgPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(p, false), p, cfgPath
}

// mintKey makes a real keypair, since the importer fingerprints what it adopts.
func mintKey(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
}

// The adoption path end to end: a host whose IdentityFile sits outside the
// managed tree has its key copied in, and the copy must be owner-only. The
// source is read with whatever mode it has - frequently 0644 for the public
// half, and not always tight for the private one - so inheriting the source
// mode would import a world-readable private key.
func TestRunAdoptsAnOutsideKeyWithTightPermissions(t *testing.T) {
	im, p, cfgPath := setupImport(t, `Host gh
    HostName github.com
    User git
    IdentityFile `+filepath.Join(t.TempDir(), "loose_key")+`
`)
	// Re-read the identity the config actually names, then mint it there.
	src := identityIn(t, cfgPath)
	mintKey(t, src)
	if err := os.Chmod(src, 0o644); err != nil { // as a careless setup would leave it
		t.Fatal(err)
	}

	res, err := im.Run(cfgPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Adopted != 1 {
		t.Fatalf("Adopted = %d, want the outside key copied in", res.Adopted)
	}
	dst := filepath.Join(p.SSHDir, "profiles", "imported", "imported_gh-ed25519")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("adopted key not at the canonical path: %v", err)
	}
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("the adopted key is not a copy of the source")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("adopted private key is %04o, want 0600 whatever the source was", mode)
		}
	}
	// Adoption copies; it does not move. The original is someone else's file.
	if _, err := os.Stat(src); err != nil {
		t.Errorf("the source key was disturbed: %v", err)
	}
	if _, err := os.Stat(p.Manifest()); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	m := mustLoad(t, p)
	hosts := m.Profiles["imported"].Hosts
	if len(hosts) != 1 || hosts[0].Alias != "gh" || hosts[0].Hostname != "github.com" {
		t.Fatalf("imported hosts = %+v", hosts)
	}
	if hosts[0].Provider == nil || *hosts[0].Provider != "github" {
		t.Errorf("provider = %v, want it inferred from the hostname", hosts[0].Provider)
	}
}

func TestDryRunWritesNothingAndAdoptsNothing(t *testing.T) {
	im, p, cfgPath := setupImport(t, `Host gh
    HostName github.com
    IdentityFile `+filepath.Join(t.TempDir(), "loose_key")+`
`)
	mintKey(t, identityIn(t, cfgPath))

	res, err := im.Run(cfgPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Profiles["imported"] != 1 {
		t.Errorf("dry run should still report what it found: %+v", res)
	}
	if res.Adopted != 0 {
		t.Errorf("Adopted = %d, want 0 in a dry run", res.Adopted)
	}
	for _, path := range []string{p.Manifest(), p.Inventory(),
		filepath.Join(p.SSHDir, "profiles", "imported", "imported_gh-ed25519")} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("dry run wrote %s", filepath.Base(path))
		}
	}
}

// Import replaces the manifest, so it can be re-run - and a re-run must not
// overwrite the keys the first run adopted. The private key on disk is the
// identity remote targets trust; replacing it with whatever the config now
// points at would silently invalidate every deployment of it.
func TestAdoptNeverOverwritesAKeyAlreadyInTheTree(t *testing.T) {
	im, p, cfgPath := setupImport(t, `Host gh
    HostName github.com
    IdentityFile `+filepath.Join(t.TempDir(), "loose_key")+`
`)
	mintKey(t, identityIn(t, cfgPath))
	dst := filepath.Join(p.SSHDir, "profiles", "imported", "imported_gh-ed25519")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	const incumbent = "the key already in the tree\n"
	if err := os.WriteFile(dst, []byte(incumbent), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := im.Run(cfgPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Adopted != 0 {
		t.Errorf("Adopted = %d, want 0 - the destination was occupied", res.Adopted)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != incumbent {
		t.Fatal("import overwrote a key already in the tree")
	}
}

// A key that already lives under its own profile is referenced where it is:
// no copy, and the name it already has rather than a derived one.
func TestAKeyAlreadyUnderItsProfileIsReferencedNotCopied(t *testing.T) {
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	existing := filepath.Join(ssh, "profiles", "work", "work_gh-ed25519")
	mintKey(t, existing)
	cfgPath := filepath.Join(ssh, "config")
	if err := os.WriteFile(cfgPath, []byte("Host gh\n    HostName github.com\n    IdentityFile "+existing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := New(p, false).Run(cfgPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Adopted != 0 {
		t.Errorf("Adopted = %d, want 0 - the key is already in place", res.Adopted)
	}
	m := mustLoad(t, p)
	hosts := m.Profiles["work"].Hosts
	if len(hosts) != 1 {
		t.Fatalf("profile from the identity path = %v", m.ProfileNames())
	}
	if hosts[0].KeyName == nil || *hosts[0].KeyName != "work_gh-ed25519" {
		t.Errorf("key_name = %v, want the name the key already has", hosts[0].KeyName)
	}
	if res.KeysFound != 1 {
		t.Errorf("KeysFound = %d, want the existing key fingerprinted into the inventory", res.KeysFound)
	}
}

// Include graphs cycle in real configs - two files that include each other, or
// a shared snippet reached by two routes. The parser has to terminate and still
// collect every host exactly once; the `seen` set of resolved absolute paths is
// what makes both true, and neither had a test.
func TestAnIncludeCycleTerminatesAndCollectsEveryHost(t *testing.T) {
	ssh := t.TempDir()
	p := paths.Paths{SSHDir: ssh, ConfigDir: t.TempDir()}
	write := func(name, body string) string {
		path := filepath.Join(ssh, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("a.conf", "Include "+filepath.Join(ssh, "b.conf")+"\nHost gh\n    HostName github.com\n")
	write("b.conf", "Include "+filepath.Join(ssh, "a.conf")+"\nHost box\n    HostName 10.0.0.2\n")
	cfgPath := write("config", "Include "+filepath.Join(ssh, "a.conf")+"\n")

	done := make(chan struct{})
	var res ImportResult
	var err error
	go func() {
		res, err = New(p, false).Run(cfgPath, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("an Include cycle did not terminate")
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Profiles["imported"] != 2 {
		t.Errorf("Profiles = %+v, want gh and box counted once each", res.Profiles)
	}
	if hosts := mustLoad(t, p).Profiles["imported"].Hosts; len(hosts) != 2 {
		t.Errorf("manifest holds %d hosts, want 2", len(hosts))
	}
}

// Appending to an ssh config rather than editing it in place is normal, so the
// same alias appearing twice is normal. The first block wins - it is the one ssh
// itself honours - and the summary must not count the loser.
func TestDuplicateHostBlocksKeepTheFirstAndAreCountedOnce(t *testing.T) {
	im, p, cfgPath := setupImport(t, `Host gh
    HostName github.com
    User git
Host gh
    HostName github.example.invalid
    User someone-else
`)
	res, err := im.Run(cfgPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Profiles["imported"] != 1 {
		t.Errorf("Profiles = %+v, want the duplicate counted once", res.Profiles)
	}
	hosts := mustLoad(t, p).Profiles["imported"].Hosts
	if len(hosts) != 1 {
		t.Fatalf("manifest holds %d hosts, want 1", len(hosts))
	}
	if hosts[0].Hostname != "github.com" || hosts[0].User != "git" {
		t.Errorf("host = %+v, want the first block's values", hosts[0])
	}
}

func TestRunRejectsAMissingConfig(t *testing.T) {
	im, _, _ := setupImport(t, "")
	if _, err := im.Run(filepath.Join(t.TempDir(), "nope"), false); err == nil {
		t.Error("importing a config that does not exist should error")
	}
}

// identityIn pulls the IdentityFile back out of the written config, so a test
// can mint the key at exactly the path the config names.
func identityIn(t *testing.T, cfgPath string) string {
	t.Helper()
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range parseSSHConfig(string(b), "", map[string]bool{}) {
		if h.IdentityFile != "" {
			return h.IdentityFile
		}
	}
	t.Fatal("no IdentityFile in the test config")
	return ""
}

func mustLoad(t *testing.T, p paths.Paths) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
