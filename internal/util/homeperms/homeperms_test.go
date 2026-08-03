package homeperms

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/internal/util/paths"
)

// The state models were absent from this enumeration, so nothing ever tightened
// them: the manifest maps every host and login the user reaches, and
// providers.json can hold deployment API tokens.
func TestStateModelsAreCovered(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(dir, ".ssh"), ConfigDir: dir}

	modes := map[string]os.FileMode{}
	for _, mp := range SecretPerms(p) {
		modes[mp.Path] = mp.Mode
	}
	for _, want := range []string{p.Manifest(), p.Inventory(), p.Providers(), p.ExpiryCache(), p.NotifyCache()} {
		mode, ok := modes[want]
		if !ok {
			t.Errorf("%s is not covered by the perms enumeration", filepath.Base(want))
			continue
		}
		if mode != FileMode {
			t.Errorf("%s should be %o, got %o", filepath.Base(want), FileMode, mode)
		}
	}
}

// A bundle's .contents sidecar names every key in the archive, and a rotated
// audit log is as sensitive as the live one.
func TestSidecarsAndRotatedLogsAreCovered(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(dir, ".ssh"), ConfigDir: dir}
	for _, d := range []string{p.DistDir(), p.LogDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	made := []string{
		filepath.Join(p.DistDir(), "ssh-manager-20260101.age"),
		filepath.Join(p.DistDir(), "ssh-manager-20260101.age.sha256"),
		filepath.Join(p.DistDir(), "ssh-manager-20260101.age.contents"),
		filepath.Join(p.LogDir(), "audit.log.1"),
	}
	for _, f := range made {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	covered := map[string]bool{}
	for _, mp := range SecretPerms(p) {
		if mp.Mode == FileMode {
			covered[mp.Path] = true
		}
	}
	for _, f := range made {
		if !covered[f] {
			t.Errorf("%s is not covered by the perms enumeration", filepath.Base(f))
		}
	}
}
