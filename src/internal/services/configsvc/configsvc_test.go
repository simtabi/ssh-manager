package configsvc

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// profiles deliberately NOT alphabetical, to prove Check reports in file order.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "work": {"key_scope": "per_service", "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git"}]},
    "alpha": {"key_scope": "per_service", "hosts": [{"alias": "a", "hostname": "a.com", "user": "u"}]}
  }
}`

func TestInSyncFormatHasCheck(t *testing.T) {
	r := &CheckResult{}
	if got := r.Format(); got != "config: in sync with the manifest ✓" {
		t.Errorf("in-sync format = %q (want the checkmark form, matching v1)", got)
	}
}

func TestCheckMissingSingleFile(t *testing.T) {
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		t.Fatal(err)
	}
	// Empty ~/.ssh -> the one rendered file (everything is inline now) is missing.
	svc := New(t.TempDir(), &m, false)
	res, err := svc.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config"}
	if len(res.Missing) != len(want) || res.Missing[0] != want[0] {
		t.Fatalf("missing=%v want %v", res.Missing, want)
	}
	if res.InSync() {
		t.Error("empty tree must not be in sync")
	}
	if !strings.HasPrefix(res.Format(), "MISSING  config (") {
		t.Errorf("format should start with the root config MISSING line:\n%s", res.Format())
	}
}

// Write is the function that actually produces ~/.ssh/config, and it had no
// test. Verified against the v2 contract, not v1's output: v2 renders one
// inline file where v1 rendered a root config plus one per profile and
// stitched them with Include (deviation D4, question Q3).

func load(t *testing.T, raw string) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestWriteProducesOneFileAndIsIdempotent(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, manifestJSON), false)

	res, err := svc.Write(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != 1 || res.Written[0] != "config" {
		t.Fatalf("written = %v, want just the one inline config", res.Written)
	}
	body, err := os.ReadFile(filepath.Join(ssh, "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host gh", "Host a", "Host *"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q:\n%s", want, body)
		}
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(ssh, "config"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("config mode = %o, want 600", fi.Mode().Perm())
		}
	}

	// Writing again changes nothing and says so.
	res, err = svc.Write(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != 0 || len(res.Unchanged) != 1 {
		t.Errorf("second write: written=%v unchanged=%v, want no writes", res.Written, res.Unchanged)
	}
	if !mustCheck(t, svc).InSync() {
		t.Error("the config should be in sync with the manifest it was rendered from")
	}
}

// mustCheck is Check without the ssh -G leg, which needs ssh on PATH. A plain
// helper rather than a method: a test file should not be adding methods to the
// production type.
func mustCheck(t *testing.T, s *Service) *CheckResult {
	t.Helper()
	res, err := s.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestWriteDryRunTouchesNothing(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, manifestJSON), false)

	res, err := svc.Write(true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || len(res.Written) != 1 {
		t.Fatalf("dry run should plan one write: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(ssh, "config")); err == nil {
		t.Error("a dry run must not write the config")
	}
}

// The v2 layout contract: a profiles/<p>/config left over from the old layout
// is pruned, because the renderer no longer produces that path. This is how a
// tree migrated from v1 stops carrying dead per-profile files that ssh would
// never read again - the root config no longer Includes them.
func TestLegacyPerProfileConfigsArePruned(t *testing.T) {
	ssh := t.TempDir()
	legacy := filepath.Join(ssh, "profiles", "work", "config")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("Host old\n    HostName old.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(ssh, load(t, manifestJSON), false)

	res, err := svc.Write(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pruned) != 1 || res.Pruned[0] != "profiles/work/config" {
		t.Fatalf("pruned = %v, want the legacy per-profile config", res.Pruned)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Error("the legacy config should have been removed from disk")
	}
	// The keys beside it are untouched: only config files are pruned.
	key := filepath.Join(ssh, "profiles", "work", "work_gh-ed25519")
	if err := os.WriteFile(key, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Errorf("a key file beside the legacy config was removed: %v", err)
	}
}

// Content outside the managed markers survives a write. An OrbStack Include or
// a hand-written Host block is not ours to delete.
func TestWritePreservesForeignContent(t *testing.T) {
	ssh := t.TempDir()
	const foreign = "# added by OrbStack\nInclude ~/.orbstack/ssh/config\n\n"
	const trailer = "\n# my own notes\nHost legacy\n    HostName legacy.example\n"
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte(foreign+trailer), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(ssh, load(t, manifestJSON), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(ssh, "config"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, want := range []string{"Include ~/.orbstack/ssh/config", "Host legacy", "Host gh"} {
		if !strings.Contains(got, want) {
			t.Errorf("write lost %q:\n%s", want, got)
		}
	}
	// And a second write does not duplicate the managed block.
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(filepath.Join(ssh, "config"))
	if n := strings.Count(string(body), "Host gh\n"); n != 1 {
		t.Errorf("the managed block was written %d times:\n%s", n, body)
	}
}

// A config edited by hand is drift, and Check has to show what changed - the
// user needs to see it before `config render` overwrites their edit.
func TestCheckReportsDriftWithADiff(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, manifestJSON), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(ssh, "config")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), "HostName github.com", "HostName evil.example", 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	res := mustCheck(t, svc)
	if res.InSync() {
		t.Fatal("an edited config is not in sync")
	}
	diff, ok := res.FileDiffs["config"]
	if !ok || diff == "" {
		t.Fatalf("no diff reported: %+v", res)
	}
	for _, want := range []string{"evil.example", "github.com"} {
		if !strings.Contains(diff, want) {
			t.Errorf("the diff should show both sides, missing %q:\n%s", want, diff)
		}
	}
	if !strings.Contains(res.Format(), "config") {
		t.Errorf("the report should name the drifted file:\n%s", res.Format())
	}
}

// Show with no alias dumps what would be rendered, so a user can inspect it
// without writing anything.
func TestShowRendersWithoutWriting(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, manifestJSON), false)

	out, err := svc.Show("")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# === config ===", "Host gh", "Host *"} {
		if !strings.Contains(out, want) {
			t.Errorf("show missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(ssh, "config")); err == nil {
		t.Error("show must not write the config")
	}
}

const categorizedJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519"},
  "profiles": {
    "personal": {"category": "internal", "key_scope": "per_service",
      "hosts": [{"alias": "gh", "hostname": "github.com", "user": "git"}]}
  }
}`

func TestWriteRendersCategoryFilesAndChecksThem(t *testing.T) {
	ssh := t.TempDir()
	svc := New(ssh, load(t, categorizedJSON), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ssh, "profiles", "internal", "config"))
	if err != nil {
		t.Fatalf("category file not written: %v", err)
	}
	if !strings.Contains(string(b), "Host gh\n") {
		t.Errorf("category file is missing its host:\n%s", b)
	}
	chk, err := svc.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	if !chk.InSync() {
		t.Errorf("a freshly written tree must be in sync:\n%s", chk.Format())
	}
}

// A user who split their config by hand before sshmgr knew about categories has
// a headerless profiles/<category>/config beside profile directories. Pruning
// it, as the legacy rule would, takes every host in it offline.
func TestHandWrittenCategoryFileIsNeverPruned(t *testing.T) {
	ssh := t.TempDir()
	hand := filepath.Join(ssh, "profiles", "others", "config")
	if err := os.MkdirAll(filepath.Join(ssh, "profiles", "others", "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hand, []byte("Host unc\n    HostName sc.its.unc.edu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(ssh, load(t, manifestJSON), false)
	res, err := svc.Write(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pruned) != 0 {
		t.Fatalf("pruned %v, want nothing: the file is not sshmgr's", res.Pruned)
	}
	if _, err := os.Stat(hand); err != nil {
		t.Errorf("the hand-written category file was removed: %v", err)
	}
	chk, err := svc.Check(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(chk.Orphan) != 0 {
		t.Errorf("a file sshmgr does not own is not its orphan: %v", chk.Orphan)
	}
}

// A category sshmgr rendered and the manifest then dropped is sshmgr's file,
// header and all, and is pruned like any other stale managed file.
func TestRenderedCategoryFileIsPrunedWhenTheCategoryGoes(t *testing.T) {
	ssh := t.TempDir()
	if _, err := New(ssh, load(t, categorizedJSON), false).Write(false); err != nil {
		t.Fatal(err)
	}
	res, err := New(ssh, load(t, manifestJSON), false).Write(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pruned) != 1 || res.Pruned[0] != "profiles/internal/config" {
		t.Fatalf("pruned = %v, want the dropped category's file", res.Pruned)
	}
}

// `config check` promises a non-zero exit when the config is not fit to use. A
// config ssh cannot parse is the worst case of that, so an ssh -G failure fails
// InSync - it used to be reported and then ignored, exiting 0.
func TestSSHErrorsFailInSync(t *testing.T) {
	r := &CheckResult{SSHErrors: map[string]string{"gh": "config line 2: invalid quotes"}}
	if r.InSync() {
		t.Error("a config ssh rejects was reported in sync")
	}
	if !strings.Contains(r.Format(), "SSH -G   gh: config line 2: invalid quotes") {
		t.Errorf("format lost the ssh error:\n%s", r.Format())
	}
}

// End to end against the real ssh: the managed block matches the manifest byte
// for byte, but hand-written content above it has a stray quote, so ssh refuses
// the whole file. Without the ssh leg (validateSSH=false) nothing changes.
func TestCheckFailsWhenSSHCannotParseTheConfig(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not on PATH")
	}
	dir := t.TempDir()
	svc := New(dir, load(t, manifestJSON), false)
	if _, err := svc.Write(false); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config")
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	foreign := "Host broken\n    HostName \"unterminated\n\n"
	if err := os.WriteFile(cfg, []byte(foreign+string(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mustCheck(t, svc).InSync() {
		t.Fatal("foreign content alone should not be drift")
	}
	res, err := svc.Check(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SSHErrors) == 0 {
		t.Fatal("ssh -G accepted a config with an unterminated quote")
	}
	if res.InSync() {
		t.Errorf("a config ssh cannot parse was reported in sync:\n%s", res.Format())
	}
}
