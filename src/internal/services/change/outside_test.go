package change

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// marker is a change whose only work is outside the copy: it writes a file
// next to the home, which a preview must never do.
func marker(p paths.Paths, effects bool) (Change, string) {
	path := filepath.Join(filepath.Dir(p.ConfigDir), "outside")
	ch := Change{
		Command: "test outside", NoSnapshot: true,
		OnApply: func(_ paths.Paths, out io.Writer) error {
			_, _ = fmt.Fprintln(out, "wrote it")
			return os.WriteFile(path, []byte("x"), 0o600)
		},
		Run: func(paths.Paths, io.Writer) error { return nil },
	}
	if effects {
		ch.Effects = func(paths.Paths) ([]string, error) { return []string{"writes outside"}, nil }
	}
	return ch, path
}

// OnApply is the part of a change a copy cannot hold, so a preview must not
// run it, and apply must.
func TestOnApplyRunsOnApplyOnly(t *testing.T) {
	p := home(t)
	ch, path := marker(p, true)
	plan, err := Preview(p, ch)
	if err != nil || plan.Err != "" {
		t.Fatalf("preview: %v %s", err, plan.Err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the preview ran the part that acts outside the copy")
	}
	if !slices.Contains(plan.Effects, "writes outside") {
		t.Errorf("effects = %v", plan.Effects)
	}
	_, res, err := Apply(p, ch, plan.Hash, 10, history.SourceWeb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("apply did not run OnApply")
	}
	if !strings.Contains(res.Output, "wrote it") {
		t.Errorf("output = %q", res.Output)
	}
}

// A change that acts outside the copy and does not say how could be confirmed
// unseen, so it is refused before anything is shown.
func TestOnApplyWithoutEffectsIsRefused(t *testing.T) {
	p := home(t)
	ch, _ := marker(p, false)
	if _, err := Preview(p, ch); err == nil || !strings.Contains(err.Error(), "needs Effects") {
		t.Fatalf("err = %v", err)
	}
}

// A purge deletes private keys, which the copy holds only as placeholders. The
// preview says which, the real keys survive it, and without a backup recipient
// it is refused outright.
func TestPurgeShowsTheKeysItDeletesAndNeedsABackup(t *testing.T) {
	p := home(t)
	key := filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")

	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	plan, err := Preview(p, ProfilePurge("work"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Err, "SSH_MANAGER_AGE_RECIPIENT") {
		t.Errorf("a purge with no backup recipient should be refused: %q", plan.Err)
	}

	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "age1placeholderforthepreviewonly")
	plan, err = Preview(p, ProfilePurge("work"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Err != "" && !strings.Contains(plan.Err, "age is not installed") {
		t.Fatalf("plan.Err = %s", plan.Err)
	}
	if plan.Err == "" && !slices.Contains(plan.Hidden, "removes ~/.ssh/profiles/work/work_gh-ed25519") {
		t.Errorf("the private key it deletes is not named: %v", plan.Hidden)
	}
	if b, err := os.ReadFile(key); err != nil || !strings.Contains(string(b), privateMarker) {
		t.Error("the preview touched the real private key")
	}
}

// A category move carries the private keys along: both ends are named.
func TestCategoryMoveNamesTheKeysItMoves(t *testing.T) {
	p := home(t)
	plan, err := Preview(p, ProfileCategory("work", "clients"))
	if err != nil || plan.Err != "" {
		t.Fatalf("%v %s", err, plan.Err)
	}
	want := []string{
		"creates ~/.ssh/profiles/clients/work/work_gh-ed25519",
		"removes ~/.ssh/profiles/work/work_gh-ed25519",
	}
	if !slices.Equal(plan.Hidden, want) {
		t.Errorf("hidden = %v, want %v", plan.Hidden, want)
	}
	if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")); err != nil {
		t.Error("the preview moved the real key")
	}
}

// The bundles a --keep would remove are listed, counting the new one.
func TestBundleListsTheBundlesItPrunes(t *testing.T) {
	p := home(t)
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "age1placeholderforthepreviewonly")
	if err := os.MkdirAll(p.DistDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ssh-manager-20260101-000000.age", "ssh-manager-20260102-000000.age"} {
		if err := os.WriteFile(filepath.Join(p.DistDir(), n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := Preview(p, Bundle(2))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.Err, "age is not installed") {
		t.Skip("age not installed")
	}
	if !slices.Contains(plan.Effects, "removes bundle ssh-manager-20260101-000000.age") ||
		slices.Contains(plan.Effects, "removes bundle ssh-manager-20260102-000000.age") {
		t.Errorf("effects = %v", plan.Effects)
	}
}

// A restore previews the snapshot it names into the copy, binds the
// confirmation to that file, and refuses a snapshot that holds private keys.
func TestSnapshotRestorePreviewsAndRefusesKeyBearingSnapshots(t *testing.T) {
	p := home(t)
	cfg := filepath.Join(p.SSHDir, "config")
	if err := os.WriteFile(cfg, []byte("Host old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshots.Snapshot(p.SSHDir, p.SnapshotsDir(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("Host new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(snap)
	plan, err := Preview(p, SnapshotRestore(p.SnapshotsDir(), id, 10))
	if err != nil || plan.Err != "" {
		t.Fatalf("%v %s", err, plan.Err)
	}
	if !slices.Contains(plan.Effects, "restores "+id) {
		t.Errorf("effects = %v", plan.Effects)
	}
	if len(plan.Files) != 1 || plan.Files[0].Path != "~/.ssh/config" {
		t.Fatalf("files = %+v", plan.Files)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "Host new\n" {
		t.Error("the preview restored the real config")
	}
	_, _, err = Apply(p, SnapshotRestore(p.SnapshotsDir(), id, 10), plan.Hash, 10, history.SourceWeb)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "Host old\n" {
		t.Errorf("config after restore = %q", b)
	}

	// A legacy snapshot with a private key in it is not restored from here.
	legacy := filepath.Join(p.SnapshotsDir(), "ssh-20200101-000000.tar.gz")
	writeKeyBearingSnapshot(t, legacy)
	plan, err = Preview(p, SnapshotRestore(p.SnapshotsDir(), filepath.Base(legacy), 10))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Err, "holds private keys") {
		t.Errorf("a key-bearing snapshot was not refused: %q", plan.Err)
	}
}

// writeKeyBearingSnapshot writes a snapshot in the old shape, with a file in
// it that is not one a snapshot may hold.
func writeKeyBearingSnapshot(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("stands in for a private key\n")
	if err := tw.WriteHeader(&tar.Header{Name: ".ssh/id_ed25519", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()
}
