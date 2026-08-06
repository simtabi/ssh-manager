package homeperms

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
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

// Every directory in the config home is owner-only, and the two files that are
// secrets in the plainest sense are covered by name: age-identity.txt decrypts
// every bundle the user has ever taken, and .env holds the provider tokens.
func TestDirectoriesAndTheAgeIdentityAreCovered(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(dir, ".ssh"), ConfigDir: dir}
	modes := map[string]os.FileMode{}
	for _, mp := range SecretPerms(p) {
		modes[mp.Path] = mp.Mode
	}

	for _, d := range []string{p.ConfigDir, p.LogDir(), p.StateDir(), p.SnapshotsDir(), p.DistDir()} {
		mode, ok := modes[d]
		if !ok {
			t.Errorf("%s is not covered by the perms enumeration", filepath.Base(d))
			continue
		}
		if mode != DirMode {
			t.Errorf("%s should be %04o, got %04o", filepath.Base(d), DirMode, mode)
		}
	}
	for _, f := range []string{p.AgeIdentity(), p.EnvFile(), p.AuditLog(), p.LockFile()} {
		mode, ok := modes[f]
		if !ok {
			t.Errorf("%s is not covered by the perms enumeration", filepath.Base(f))
			continue
		}
		if mode != FileMode {
			t.Errorf("%s should be %04o, got %04o", filepath.Base(f), FileMode, mode)
		}
	}
}

// The identity file is only conventionally named age-identity.txt; a user who
// points SSH_MANAGER_AGE_IDENTITY_FILE at another name in the same directory
// gets a file that decrypts every bundle, so the glob has to catch it wherever
// it sits - and so do bundles written to the config home rather than dist/.
func TestIdentitiesAndBundlesAreCoveredWhereverTheyLandInTheHome(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(dir, ".ssh"), ConfigDir: dir}
	made := []string{
		filepath.Join(p.ConfigDir, "work-identity.txt"),
		filepath.Join(p.ConfigDir, "ssh-manager-20260101.age"),
		filepath.Join(p.ConfigDir, "ssh-manager-20260101.age.sha256"),
	}
	for _, f := range made {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	covered := map[string]os.FileMode{}
	for _, mp := range SecretPerms(p) {
		covered[mp.Path] = mp.Mode
	}
	for _, f := range made {
		mode, ok := covered[f]
		if !ok {
			t.Errorf("%s is not covered by the perms enumeration", filepath.Base(f))
			continue
		}
		if mode != FileMode {
			t.Errorf("%s should be %04o, got %04o", filepath.Base(f), FileMode, mode)
		}
	}
}
