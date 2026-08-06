package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

func fixture(t *testing.T) paths.Paths {
	t.Helper()
	base := t.TempDir()
	releaseHeldLock(t)
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	key := filepath.Join(p.SSHDir, "profiles", "work", "work_gh-ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Destroying key material used to be safe by accident: the pre-mutation snapshot
// held every private key. Now that it does not, an operation that discards a key
// has to stop rather than proceed with no way back.
func TestNoRecipientRefusesToDestroyKeys(t *testing.T) {
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	var out strings.Builder

	err := backupKeysBeforeDestroying(fixture(t), &out, false)
	if err == nil {
		t.Fatal("expected a refusal when no backup can be written")
	}
	// The message has to say how to get unstuck, both ways.
	for _, want := range []string{"SSH_MANAGER_AGE_RECIPIENT", "--no-key-backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %s: %v", want, err)
		}
	}
}

// The opt-out proceeds, but says plainly what it is giving up.
func TestOptOutWarnsInsteadOfRefusing(t *testing.T) {
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "")
	var out strings.Builder

	if err := backupKeysBeforeDestroying(fixture(t), &out, true); err != nil {
		t.Fatalf("--no-key-backup should proceed: %v", err)
	}
	if !strings.Contains(out.String(), "unrecoverable") {
		t.Errorf("the opt-out should state the consequence: %q", out.String())
	}
}

// With a recipient configured, a bundle is actually written before the caller
// destroys anything.
func TestBackupIsWrittenWhenRecipientIsSet(t *testing.T) {
	if !hasAge() {
		t.Skip("age not installed")
	}
	recipient, _ := ageIdentity(t)
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", recipient)
	p := fixture(t)
	var out strings.Builder

	if err := backupKeysBeforeDestroying(p, &out, false); err != nil {
		t.Fatal(err)
	}
	bundles, _ := filepath.Glob(filepath.Join(p.DistDir(), "ssh-manager-*.age"))
	if len(bundles) != 1 {
		t.Fatalf("expected one bundle in %s, got %v", p.DistDir(), bundles)
	}
	if !strings.Contains(out.String(), "key backup:") {
		t.Errorf("the bundle path should be reported: %q", out.String())
	}
	raw, err := os.ReadFile(bundles[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE") {
		t.Error("the backup holds the key in the clear")
	}
}

// A misconfigured recipient must abort the operation rather than let it continue
// believing a backup exists.
func TestBadRecipientAbortsRatherThanContinuing(t *testing.T) {
	if !hasAge() {
		t.Skip("age not installed")
	}
	t.Setenv("SSH_MANAGER_AGE_RECIPIENT", "age1thisisnotavalidrecipient")
	p := fixture(t)
	var out strings.Builder

	err := backupKeysBeforeDestroying(p, &out, false)
	if err == nil {
		t.Fatal("a failed backup must not be reported as success")
	}
	if !strings.Contains(err.Error(), "back up keys") {
		t.Errorf("the error should name what failed: %v", err)
	}
}
