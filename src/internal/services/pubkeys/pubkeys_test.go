package pubkeys

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keystore"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/keysvc"
)

const fileManifest = `{"version":1,"profiles":{"work":{"hosts":[
  {"alias":"a","hostname":"h","user":"u","key_name":"work_a-ed25519"},
  {"alias":"b","hostname":"h","user":"u","key_name":"work_b-ed25519"}]}}}`

type fx struct {
	m   *manifest.Manifest
	inv *inventory.Inventory
	ssh string
}

func setup(t *testing.T, raw string) fx {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return fx{&m, inventory.New(), t.TempDir()}
}

func (f fx) mint(t *testing.T, ref manifest.KeyRef, passphrase string) string {
	t.Helper()
	priv := f.m.KeyPath(f.ssh, ref)
	if err := os.MkdirAll(filepath.Dir(priv), 0o700); err != nil {
		t.Fatal(err)
	}
	// ssh-keygen directly: keystore.Generate hands a passphrase over through the
	// running binary as askpass helper, and in a test that binary is the test,
	// which would run itself instead of answering.
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", ref.String(), "-f", priv).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	fp, err := keystore.New().Fingerprint(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f.inv.Record(fp, inventory.KeyRecord{Profile: ref.Profile, Path: f.m.IdentityFile(ref.Profile, ref.KeyName), Type: "ed25519"})
	return priv
}

func (f fx) regen(t *testing.T, dry bool) map[string]Result {
	t.Helper()
	rows, err := keysvc.New(f.m, f.inv, f.ssh).Select(keysvc.Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Result{}
	for _, r := range New(f.m, f.inv).Regenerate(rows, dry) {
		out[r.Ref.KeyName] = r
	}
	return out
}

func TestRegenerateCreatesRewritesAndLeavesAlone(t *testing.T) {
	f := setup(t, fileManifest)
	a := f.mint(t, manifest.KeyRef{Profile: "work", KeyName: "work_a-ed25519"}, "")
	b := f.mint(t, manifest.KeyRef{Profile: "work", KeyName: "work_b-ed25519"}, "")
	aPub, _ := os.ReadFile(a + ".pub")
	if err := os.Remove(a + ".pub"); err != nil {
		t.Fatal(err)
	}
	// b's .pub now holds a's key: the wrong public key at the right path.
	bPubBefore, _ := os.ReadFile(b + ".pub")
	if err := os.WriteFile(b+".pub", aPub, 0o644); err != nil {
		t.Fatal(err)
	}

	dry := f.regen(t, true)
	if dry["work_a-ed25519"].Action != Created || dry["work_b-ed25519"].Action != Rewritten {
		t.Fatalf("dry run = %+v", dry)
	}
	if _, err := os.Stat(a + ".pub"); err == nil {
		t.Fatal("a dry run wrote a file")
	}

	got := f.regen(t, false)
	if got["work_a-ed25519"].Action != Created || got["work_b-ed25519"].Action != Rewritten {
		t.Fatalf("results = %+v", got)
	}
	if !strings.Contains(got["work_b-ed25519"].Detail, "sshmgr deploy") {
		t.Errorf("a rewritten .pub should point at redeploying: %q", got["work_b-ed25519"].Detail)
	}
	bPubAfter, _ := os.ReadFile(b + ".pub")
	if strings.Fields(string(bPubAfter))[1] != strings.Fields(string(bPubBefore))[1] {
		t.Error("b's .pub was not restored to b's own key")
	}
	if again := f.regen(t, false); again["work_a-ed25519"].Action != Unchanged || again["work_b-ed25519"].Action != Unchanged {
		t.Errorf("a second run should change nothing: %+v", again)
	}
}

func TestRegenerateSkipsWhatItCannotDerive(t *testing.T) {
	f := setup(t, fileManifest)
	f.mint(t, manifest.KeyRef{Profile: "work", KeyName: "work_a-ed25519"}, "s3cret-passphrase")
	got := f.regen(t, false)
	if got["work_a-ed25519"].Action != Skipped || !strings.Contains(got["work_a-ed25519"].Detail, "passphrase") {
		t.Errorf("encrypted key: %+v", got["work_a-ed25519"])
	}
	if got["work_b-ed25519"].Action != Skipped || !strings.Contains(got["work_b-ed25519"].Detail, "private key is missing") {
		t.Errorf("no private key: %+v", got["work_b-ed25519"])
	}
}

func TestRegenerateReadsAOnePasswordKeyFromItsItem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake op is a shell script")
	}
	f := setup(t, `{"version":1,"profiles":{"bot":{"key_store":"1password","op_vault":"V","hosts":[
	  {"alias":"g","hostname":"github.com","user":"git","key_name":"bot_g-ed25519"}]}}}`)
	dir := t.TempDir()
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "k")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "k.pub"))
	line := strings.Join(strings.Fields(string(pub))[:2], " ")
	op := "#!/bin/sh\necho '{\"id\":\"i1\",\"title\":\"bot_g-ed25519\",\"fields\":[{\"id\":\"public_key\",\"value\":\"" + line + "\"}]}'\n"
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte(op), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := f.regen(t, false)
	if got["bot_g-ed25519"].Action != Created {
		t.Fatalf("result = %+v", got["bot_g-ed25519"])
	}
	written, _ := os.ReadFile(f.m.KeyPath(f.ssh, manifest.KeyRef{Profile: "bot", KeyName: "bot_g-ed25519"}) + ".pub")
	if !strings.HasPrefix(string(written), line) {
		t.Errorf(".pub = %q, want the item's public key", written)
	}
}
