package change

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/snapshots"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

const privateMarker = "-----BEGIN OPENSSH PRIVATE KEY-----"

func home(t *testing.T) paths.Paths {
	t.Helper()
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(p.Manifest(), `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`)
	write(p.Inventory(), `{"version":1,"keys":{}}`)
	write(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519"), privateMarker+"\n")
	write(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519.pub"), "ssh-ed25519 AAAA work\n")
	t.Cleanup(mutation.Release)
	return p
}

func everything(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[p] = string(b)
		return nil
	})
	return out
}

func web(alias string) Change {
	return HostAdd("work", alias, HostInput{Hostname: ptr(alias + ".example"), User: ptr("deploy")})
}

func ptr[T any](v T) *T { return &v }

// A preview is the change made somewhere harmless: nothing in the real home
// moves, nothing is recorded, and the diff shows the manifest and the config.
func TestPreviewChangesNothingAndShowsTheChange(t *testing.T) {
	p := home(t)
	before := everything(t, filepath.Dir(p.ConfigDir))
	plan, err := Preview(p, web("db"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Err != "" || plan.Hash == "" {
		t.Fatalf("plan = %+v", plan)
	}
	if after := everything(t, filepath.Dir(p.ConfigDir)); len(after) != len(before) {
		t.Errorf("the preview changed the home: %d files became %d", len(before), len(after))
	} else {
		for k, v := range before {
			if after[k] != v {
				t.Errorf("the preview changed %s", k)
			}
		}
	}
	got := map[string]string{}
	for _, f := range plan.Files {
		got[f.Path] = f.State
	}
	if got["config/manifest.json"] != "changed" {
		t.Errorf("the preview does not show the manifest change: %v", got)
	}
	rendered := false
	for path := range got {
		if strings.HasPrefix(path, "~/.ssh/") {
			rendered = true
		}
	}
	if !rendered {
		t.Errorf("the preview does not show what it renders into ~/.ssh: %v", got)
	}
	if !strings.Contains(plan.Output, "added host db") || strings.Contains(plan.Output, "sshmgr-preview-") {
		t.Errorf("output = %q", plan.Output)
	}
	if _, err := os.Stat(p.HistoryDB()); err == nil {
		t.Error("a preview created the history")
	}
}

// The copy a preview runs in never holds a private key.
func TestThePreviewCopyHoldsNoPrivateKey(t *testing.T) {
	p := home(t)
	seen := 0
	spy := Change{Command: "spy", Run: func(shadow paths.Paths, _ io.Writer) error {
		for path, body := range everything(t, filepath.Dir(shadow.ConfigDir)) {
			seen++
			if strings.Contains(body, privateMarker) {
				t.Errorf("the preview copied a private key: %s", path)
			}
		}
		if _, err := os.Stat(filepath.Join(shadow.SSHDir, "profiles", "work", "work_gh-ed25519.pub")); err != nil {
			t.Errorf("the public key was not copied: %v", err)
		}
		return nil
	}}
	if _, err := Preview(p, spy); err != nil {
		t.Fatal(err)
	}
	if seen < 3 {
		t.Fatalf("saw %d files in the copy; the spy is not reaching it", seen)
	}
}

// Confirming a preview that has since gone out of date is refused, with the
// new preview, and nothing is written.
func TestAStaleConfirmationIsRefused(t *testing.T) {
	p := home(t)
	plan, err := Preview(p, web("db"))
	if err != nil {
		t.Fatal(err)
	}
	// Someone else changes the manifest meanwhile.
	if err := editor.New(p).AddHost("work", "other", editor.HostFields{Hostname: ptr("o.example"), User: ptr("u"), Port: ptr(22)}); err != nil {
		t.Fatal(err)
	}
	manifestBefore, _ := os.ReadFile(p.Manifest())
	fresh, _, err := Apply(p, web("db"), plan.Hash, 10, history.SourceWeb)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Apply = %v, want ErrStale", err)
	}
	if fresh.Hash == "" || fresh.Hash == plan.Hash {
		t.Error("a stale apply should hand back the new preview")
	}
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(manifestBefore) {
		t.Error("a stale apply wrote the manifest")
	}
	if mutation.Held() {
		t.Error("a stale apply kept the lock")
	}
	ops := webOps(t, p)
	if len(ops) != 1 || ops[0].Result != history.ResultAborted {
		t.Errorf("a stale apply was recorded as %+v, want one aborted operation", ops)
	}
}

func TestApplyMakesTheChangeAndRecordsIt(t *testing.T) {
	p := home(t)
	ch := web("db")
	plan, err := Preview(p, ch)
	if err != nil {
		t.Fatal(err)
	}
	_, res, err := Apply(p, ch, plan.Hash, 10, history.SourceWeb)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p.Manifest()); !strings.Contains(string(b), `"db"`) {
		t.Error("the change was not made")
	}
	if mutation.Held() {
		t.Error("Apply kept the lock; a server would block every CLI command")
	}
	if res.Snapshot == "" || !strings.Contains(res.Output, "added host db") {
		t.Errorf("result = %+v", res)
	}
	ops := webOps(t, p)
	if len(ops) != 1 || ops[0].OpID != res.OpID || ops[0].Result != history.ResultOK || ops[0].Command != "host add" {
		t.Fatalf("recorded %+v, want the host add under %s", ops, res.OpID)
	}
	if len(ops[0].Events) == 0 || ops[0].Events[0].Event != "host.add" {
		t.Errorf("the operation has events %+v; the preview's must not appear and the real one must", ops[0].Events)
	}
	if len(ops[0].Events) != 1 {
		t.Errorf("%d events: the preview under the lock leaked its own into the record", len(ops[0].Events))
	}
}

// A change the preview says would fail is not made, and says why.
func TestAChangeThatWouldFailIsNotMade(t *testing.T) {
	p := home(t)
	ch := HostAdd("nope", "x", HostInput{Hostname: ptr("x"), User: ptr("u")})
	plan, err := Preview(p, ch)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Err == "" {
		t.Fatal("adding a host to a missing profile should fail in the preview")
	}
	before, _ := os.ReadFile(p.Manifest())
	if _, _, err := Apply(p, ch, plan.Hash, 10, history.SourceWeb); err == nil {
		t.Error("Apply made a change its preview said would fail")
	}
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(before) {
		t.Error("the manifest moved")
	}
}

func webOps(t *testing.T, p paths.Paths) []history.Op {
	t.Helper()
	s, err := history.Open(p.HistoryDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ops, err := s.Query(history.Filter{Source: history.SourceWeb})
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

// A minting change previews with a throwaway key, leaves the real home alone,
// and still applies: the hash binds to the keys it makes, not their bytes.
func TestAMintingChangePreviewsAndApplies(t *testing.T) {
	p := home(t)
	if err := HostAdd("work", "new01", HostInput{Hostname: ptr("new01.example"), User: ptr("ops")}).Run(p, io.Discard); err != nil {
		t.Fatal(err)
	}
	newKey := filepath.Join(p.SSHDir, "profiles", "work", "work_new01-ed25519")
	plan, err := Preview(p, Reconcile())
	if err != nil || plan.Err != "" {
		t.Fatalf("preview: %v %s", err, plan.Err)
	}
	if !plan.Mints {
		t.Error("the plan should say its keys are throwaway")
	}
	if _, err := os.Stat(newKey); err == nil {
		t.Fatal("the preview minted a key into the real home")
	}
	shown := false
	for _, f := range plan.Files {
		shown = shown || strings.HasSuffix(f.Path, "work_new01-ed25519.pub")
	}
	if !shown {
		t.Errorf("the preview does not show the key it would make: %+v", plan.Files)
	}
	// The existing key is not minted again: its placeholder stood in for it.
	for _, f := range plan.Files {
		if strings.HasSuffix(f.Path, "work_gh-ed25519.pub") {
			t.Errorf("the preview re-minted a key that exists: %s %s", f.Path, f.State)
		}
	}
	if _, _, err := Apply(p, Reconcile(), plan.Hash, 10, history.SourceWeb); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := os.Stat(newKey); err != nil {
		t.Error("apply did not mint the key")
	}
	if b, _ := os.ReadFile(filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")); string(b) != privateMarker+"\n" {
		t.Error("apply touched the existing private key")
	}
}

// The preview copy stands in for a private key with an empty file: present,
// so nothing re-mints it, and holding nothing of it.
func TestPlaceholdersAreEmpty(t *testing.T) {
	p := home(t)
	checked := 0
	spy := Change{Command: "spy", Run: func(shadow paths.Paths, _ io.Writer) error {
		fi, err := os.Stat(filepath.Join(shadow.SSHDir, "profiles", "work", "work_gh-ed25519"))
		if err != nil {
			t.Errorf("no placeholder for the private key: %v", err)
			return nil
		}
		checked++
		if fi.Size() != 0 {
			t.Errorf("the placeholder holds %d bytes", fi.Size())
		}
		return nil
	}}
	if _, err := Preview(p, spy); err != nil {
		t.Fatal(err)
	}
	if checked != 1 {
		t.Fatal("the spy did not run")
	}
}

// A preview mints for real, so a profile kept in 1Password is refused: the
// preview would leave an item in the vault.
func TestMintingInOnePasswordIsRefused(t *testing.T) {
	p := home(t)
	if err := os.WriteFile(p.Manifest(), []byte(`{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{
	  "work":{"key_scope":"per_service","key_store":"1password","op_vault":"Private",
	    "hosts":[{"alias":"gh","hostname":"github.com","user":"git"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []Change{Reconcile(), Keygen("work"), KeyAdd("work", "x", "", "")} {
		plan, err := Preview(p, ch)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plan.Err, "1Password") {
			t.Errorf("%s: plan.Err = %q, want the 1Password refusal", ch.Command, plan.Err)
		}
	}
}

// Prune and fix show what they do outside the files a preview copies.
func TestEffectsAreShownAndBound(t *testing.T) {
	p := home(t)
	for i := 0; i < 3; i++ {
		mutation.SnapshotBeforeMutation(p, 10)
	}
	mutation.Release()
	plan, err := Preview(p, SnapshotsPrune(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Effects) != 2 || !strings.HasPrefix(plan.Effects[0], "removes snapshot ssh-") {
		t.Errorf("effects = %v, want the two oldest snapshots", plan.Effects)
	}
	// A new snapshot changes what prune would remove, so the hash moves.
	mutation.SnapshotBeforeMutation(p, 10)
	mutation.Release()
	again, _ := Preview(p, SnapshotsPrune(1))
	if again.Hash == plan.Hash {
		t.Error("the prune preview's hash did not move when its effects did")
	}
	if _, _, err := Apply(p, SnapshotsPrune(1), again.Hash, 10, history.SourceWeb); err != nil {
		t.Fatal(err)
	}
	if n := len(snapshots.List(p.SnapshotsDir())); n != 1 {
		t.Errorf("%d snapshots left, want 1 (prune must not snapshot first)", n)
	}

	if err := os.Chmod(p.Manifest(), 0o644); err != nil {
		t.Fatal(err)
	}
	fix, _ := Preview(p, DoctorFix())
	found := false
	for _, e := range fix.Effects {
		found = found || strings.Contains(e, "manifest.json")
	}
	if !found {
		t.Errorf("doctor --fix effects %v do not name the manifest", fix.Effects)
	}
}
