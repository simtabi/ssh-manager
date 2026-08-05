package perms

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func managed(t *testing.T, ssh string) map[string]os.FileMode {
	t.Helper()
	out := map[string]os.FileMode{}
	for _, mp := range IterManagedPaths(ssh) {
		rel, err := filepath.Rel(ssh, mp.Path)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.ToSlash(rel)] = mp.Mode
	}
	return out
}

// A crashed rotation or mint leaves a real private key in .staging or .mint-*.
// Those dirs used to be skipped alongside OS cruft, so nothing ever repaired
// their modes and the key sat there at whatever the umask produced.
func TestStagingDirsAreManaged(t *testing.T) {
	ssh := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(ssh, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("PRIVATE\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("profiles/work/.staging/work_gh-ed25519")
	mk("profiles/work/.mint-1234/id_ed25519")
	mk("profiles/work/.DS_Store")

	got := managed(t, ssh)
	for _, want := range []string{
		"profiles/work/.staging",
		"profiles/work/.staging/work_gh-ed25519",
		"profiles/work/.mint-1234",
		"profiles/work/.mint-1234/id_ed25519",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s should be managed so its mode gets repaired", want)
		}
	}
	if mode, ok := got["profiles/work/.staging/work_gh-ed25519"]; ok && mode != PrivateKeyMode {
		t.Errorf("staged key should be %o, got %o", PrivateKeyMode, mode)
	}
	if mode, ok := got["profiles/work/.staging"]; ok && mode != DirMode {
		t.Errorf("staging dir should be %o, got %o", DirMode, mode)
	}
	if _, ok := got["profiles/work/.DS_Store"]; ok {
		t.Error("foreign dotfiles are not ours to chmod")
	}
}

// SetPerms follows the path it is given, so a managed path that is a symlink
// would have the mode applied to whatever it points at - a file in the dotfiles
// repo, or anything else on the machine. Every level skips them: ~/.ssh itself,
// the two top-level files, profiles/, and each entry underneath.
func TestSymlinksAreNeverManagedAtAnyLevel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	outside := t.TempDir()
	target := filepath.Join(outside, "someone-elses-file")
	if err := os.WriteFile(target, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ssh := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ssh, "profiles", "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := func(rel string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(ssh, rel)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	link("config")
	link("known_hosts")
	link("profiles/work/work_gh-ed25519")

	got := managed(t, ssh)
	for _, rel := range []string{"config", "known_hosts", "profiles/work/work_gh-ed25519"} {
		if _, ok := got[rel]; ok {
			t.Errorf("%s is a symlink; chmodding it would change the file it points at", rel)
		}
	}

	// A symlinked ~/.ssh yields nothing at all rather than a tree rooted outside.
	linkedSSH := filepath.Join(outside, ".ssh")
	if err := os.Symlink(ssh, linkedSSH); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if mps := IterManagedPaths(linkedSSH); mps != nil {
		t.Errorf("a symlinked ~/.ssh should be managed not at all, got %d paths", len(mps))
	}

	// A symlinked profiles/ leaves the top-level entries but does not descend.
	ssh2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(ssh2, "config"), []byte("# c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ssh, "profiles"), filepath.Join(ssh2, "profiles")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got2 := managed(t, ssh2)
	if _, ok := got2["config"]; !ok {
		t.Error("a symlinked profiles/ should not stop the real config being managed")
	}
	if _, ok := got2["profiles"]; ok {
		t.Error("a symlinked profiles/ was managed")
	}
}

// The enumeration is deliberately narrow: ~/.ssh, the root config, the trust
// store, and profiles/. Everything else in ~/.ssh belongs to the user - a
// hand-made id_rsa, an agent socket, another tool's config - and chmodding it
// would be this tool reaching outside what it created.
func TestOnlyTheToolsOwnPathsAreManaged(t *testing.T) {
	ssh := t.TempDir()
	for _, name := range []string{"config", "known_hosts", "id_rsa", "id_rsa.pub", "authorized_keys", "config.d"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(ssh, "profiles", "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "profiles", "work", "work_gh-ed25519"), []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := managed(t, ssh)
	for _, rel := range []string{"config", "known_hosts", ".", "profiles", "profiles/work", "profiles/work/work_gh-ed25519"} {
		if _, ok := got[rel]; !ok {
			t.Errorf("%s should be managed", rel)
		}
	}
	for _, rel := range []string{"id_rsa", "id_rsa.pub", "authorized_keys", "config.d"} {
		if _, ok := got[rel]; ok {
			t.Errorf("%s is the user's file, not ours to chmod", rel)
		}
	}
}

// The mode a path gets is decided by its role, and known_hosts is the one that
// is not what a reader expects: ssh has never needed the trust store
// world-readable, and its contents are an inventory of every host the user
// connects to - the same reason the names in it are hashed.
func TestModeForKnowsWhichPathsAreSecret(t *testing.T) {
	cases := map[string]os.FileMode{
		"/x/.ssh/config":                ConfigMode,
		"/x/.ssh/known_hosts":           KnownHostsMode,
		"/x/.ssh/profiles/w/k.pub":      PublicKeyMode,
		"/x/.ssh/profiles/w/k":          PrivateKeyMode,
		"/x/.ssh/profiles/w/old/k":      PrivateKeyMode,
		"/x/.ssh/profiles/w/.staging/k": PrivateKeyMode,
	}
	for path, want := range cases {
		if got := ModeFor(filepath.FromSlash(path), false); got != want {
			t.Errorf("ModeFor(%q) = %04o, want %04o", path, got, want)
		}
	}
	if KnownHostsMode != 0o600 {
		t.Errorf("KnownHostsMode = %04o; the trust store lists every host the user talks to", KnownHostsMode)
	}
	if got := ModeFor("/x/.ssh/profiles/w", true); got != DirMode {
		t.Errorf("ModeFor(dir) = %04o, want %04o", got, DirMode)
	}
	// A directory is a directory whatever it is called - including one named
	// like a public key, which the name-based switch would otherwise call 0644.
	if got := ModeFor("/x/.ssh/profiles/w/odd.pub", true); got != DirMode {
		t.Errorf("ModeFor(dir named *.pub) = %04o, want %04o", got, DirMode)
	}
}
