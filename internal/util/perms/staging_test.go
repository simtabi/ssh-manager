package perms

import (
	"os"
	"path/filepath"
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
