package snapshots

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// keygen mints an unencrypted ed25519 pair at priv, replacing any pair there -
// the shape `keygen --force --no-key-backup` leaves on disk.
func keygen(t *testing.T, priv string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	if err := os.MkdirAll(filepath.Dir(priv), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(priv)
	_ = os.Remove(priv + ".pub")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", priv).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
}

// derived is what ssh actually offers for priv: the public half computed from
// the private key, not whatever .pub happens to sit beside it.
func derived(t *testing.T, priv string) string {
	t.Helper()
	out, err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", priv).Output()
	if err != nil {
		t.Fatalf("ssh-keygen -y: %v", err)
	}
	return keyBody(string(out))
}

func keyBody(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

func readBody(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return keyBody(string(b))
}

// Snapshots carry the .pub but never the private key, so a key regenerated after
// the snapshot would get its predecessor's public half written beside it. That
// pair no longer matches: validate fails it, and deploy would install a key
// nothing on this machine can use - while the old key stays authorised.
func TestRestoreNeverPairsAPrivateKeyWithAForeignPublicKey(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	snaps := filepath.Join(base, "snapshots")
	writeTree(t, ssh)
	priv := filepath.Join(ssh, "profiles/work/work_gh-ed25519")
	keygen(t, priv)
	tarball, err := Snapshot(ssh, snaps, 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}

	keygen(t, priv) // the key is regenerated after the snapshot
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte("CHANGED\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := readBody(t, priv+".pub"), derived(t, priv); got != want {
		t.Errorf("restore wrote a .pub that does not derive from the private key beside it:\n .pub    %s\n derived %s", got, want)
	}
	// Skipping the .pub must not cost the rest of the restore.
	if got, _ := os.ReadFile(filepath.Join(ssh, "config")); string(got) != "# root config\n" {
		t.Errorf("config not restored: %q", got)
	}
}

// The skip is only for a .pub that would break a pair. Every other .pub restores
// as before: one the private key on disk proves is its own, and one with no
// private key on disk at all - a 1Password profile keeps only the .pub locally.
func TestRestoreStillPutsBackPublicKeysThatBelong(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	priv := filepath.Join(ssh, "profiles/work/work_gh-ed25519")
	keygen(t, priv)
	opPub := filepath.Join(ssh, "profiles/vault/vault_gh-ed25519.pub")
	if err := os.MkdirAll(filepath.Dir(opPub), 0o700); err != nil {
		t.Fatal(err)
	}
	const opLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnePasswordKeptOnlyThePublicHalfHere vault\n"
	if err := os.WriteFile(opPub, []byte(opLine), 0o644); err != nil {
		t.Fatal(err)
	}
	want := readBody(t, priv+".pub")
	tarball, err := Snapshot(ssh, filepath.Join(base, "snapshots"), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}

	// Both .pub files lost; the private key is unchanged.
	_ = os.Remove(priv + ".pub")
	_ = os.Remove(opPub)

	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(priv + ".pub"); err != nil {
		t.Fatalf("the .pub that belongs to the private key on disk was not restored: %v", err)
	}
	if got := readBody(t, priv+".pub"); got != want {
		t.Errorf(".pub = %s, want %s", got, want)
	}
	if got, err := os.ReadFile(opPub); err != nil || string(got) != opLine {
		t.Errorf("a .pub with no private key on disk was not restored: %q (%v)", got, err)
	}
}

// A snapshot from before private keys were excluded carries both halves. They
// travel as a pair, so the .pub restores with the key it came with.
func TestRestoreOfALegacyArchiveKeepsItsPairTogether(t *testing.T) {
	base := t.TempDir()
	ssh := filepath.Join(base, ".ssh")
	writeTree(t, ssh)
	// The pair the legacy archive holds.
	legacy := filepath.Join(base, "legacy", "k")
	keygen(t, legacy)
	privBytes, _ := os.ReadFile(legacy)
	pubBytes, _ := os.ReadFile(legacy + ".pub")
	// A different key on disk under the same name.
	priv := filepath.Join(ssh, "profiles/work/work_gh-ed25519")
	keygen(t, priv)

	// The .pub comes first, as a tar written in readdir order can have it: when
	// it is checked, the private key on disk is still the other one.
	tarball := filepath.Join(base, "legacy.tar.gz")
	craftOrderedArchive(t, tarball, [][2]string{
		{".ssh/profiles/work/work_gh-ed25519.pub", string(pubBytes)},
		{".ssh/profiles/work/work_gh-ed25519", string(privBytes)},
	})
	if err := Restore(tarball, ssh); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := readBody(t, priv+".pub"), derived(t, priv); got != want {
		t.Errorf("legacy pair split on restore:\n .pub    %s\n derived %s", got, want)
	}
	if got := readBody(t, priv+".pub"); got != keyBody(string(pubBytes)) {
		t.Errorf("the archive's own .pub was not restored with its private key")
	}
}

// craftOrderedArchive is craftArchive with the member order given rather than
// sorted.
func craftOrderedArchive(t *testing.T, p string, members [][2]string) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: m[0], Mode: 0o600, Size: int64(len(m[1])), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// What was skipped is reported, so a rollback that left a .pub alone does not
// read as one that restored everything.
func TestRestoreByIDInReportsTheSkippedPublicKey(t *testing.T) {
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "config")}
	writeTree(t, p.SSHDir)
	priv := filepath.Join(p.SSHDir, "profiles/work/work_gh-ed25519")
	keygen(t, priv)
	if _, err := Snapshot(p.SSHDir, p.SnapshotsDir(), 10, "20260101-000000"); err != nil {
		t.Fatal(err)
	}
	keygen(t, priv)

	res, err := RestoreByIDIn(p, 10, "20260101")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	want := "profiles/work/work_gh-ed25519.pub"
	if !slices.Contains(res.Skipped, want) {
		t.Errorf("Skipped = %q, want it to name %s", res.Skipped, want)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("Skipped = %q, want exactly the one mismatched .pub", res.Skipped)
	}
}

// Dev mode puts the sandbox's ~/.ssh at <root>/ssh, so the ".ssh" name guard
// refused every sandboxed restore. The sandbox is accepted because the layout
// says it is one - not because the directory happens to be called "ssh".
func TestRestoreByIDInAcceptsTheDevSandboxAndNothingElse(t *testing.T) {
	root := t.TempDir()
	dev := paths.Paths{
		SSHDir:    filepath.Join(root, paths.DevSSHDir),
		ConfigDir: filepath.Join(root, paths.DevConfigDir),
		DevRoot:   root,
	}
	writeTree(t, dev.SSHDir)
	tarball, err := Snapshot(dev.SSHDir, dev.SnapshotsDir(), 10, "20260101-000000")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dev.SSHDir, "config"), []byte("CHANGED\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreByIDIn(dev, 10, ""); err != nil {
		t.Fatalf("restore in the dev sandbox: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dev.SSHDir, "config")); string(got) != "# root config\n" {
		t.Errorf("config not restored in the sandbox: %q", got)
	}

	// Outside dev mode the same directory is just one called "ssh". The refusal
	// comes before the pre-restore snapshot, which could otherwise prune one.
	real := dev
	real.DevRoot = ""
	before := len(List(dev.SnapshotsDir()))
	if _, err := RestoreByIDIn(real, 10, ""); err == nil {
		t.Error("a directory named ssh outside dev mode should still be refused")
	}
	if after := len(List(dev.SnapshotsDir())); after != before {
		t.Errorf("a refused restore still took a snapshot: %d -> %d", before, after)
	}
	if err := Restore(tarball, dev.SSHDir); err == nil {
		t.Error("Restore has no layout to vouch for <root>/ssh and should still refuse it")
	}
	// In dev mode, only the sandbox's own ssh dir - not any "ssh" elsewhere.
	stray := dev
	stray.SSHDir = filepath.Join(t.TempDir(), paths.DevSSHDir)
	writeTree(t, stray.SSHDir)
	if _, err := Snapshot(stray.SSHDir, stray.SnapshotsDir(), 10, "20260101-000001"); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreByIDIn(stray, 10, ""); err == nil {
		t.Error("an ssh dir outside the dev root should be refused even in dev mode")
	}
}
