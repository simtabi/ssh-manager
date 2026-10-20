package rotator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/providers"
)

// A web-panel target (Ploi) cannot take a key through an API, so rotate used to either abort or,
// with --allow-unverified, commit before the key was pasted and lock the user out until they did.
// With a manual step it waits for the paste, then proves the staged key logs in over SSH.

type manualCall struct{ alias, where, pubkey string }

func TestManualTargetIsPastedThenProvenOverSSH(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	var calls []manualCall
	var proved []providers.Target
	r := New(p, m, inv).WithManualStep(func(alias, where, pubkey string) bool {
		calls = append(calls, manualCall{alias, where, pubkey})
		return true
	})
	r.sshVerify = func(tgt providers.Target) bool { proved = append(proved, tgt); return true }

	report, err := r.Rotate(keyName, false, "") // no --allow-unverified
	if err != nil {
		t.Fatal(err)
	}
	if !report.Committed {
		t.Fatalf("a pasted key proven over SSH must commit: %+v", report)
	}
	if len(calls) != 1 || calls[0].alias != "panel" || !strings.Contains(calls[0].where, "ploi.io") ||
		!strings.HasPrefix(calls[0].pubkey, "ssh-ed25519 ") {
		t.Fatalf("manual step calls = %+v", calls)
	}
	if len(proved) != 1 || !strings.Contains(proved[0].IdentityPath, ".staging") ||
		proved[0].SSHDest() != "x@ploi.example" {
		t.Fatalf("the proof must log in with the STAGED key, as the host's user: %+v", proved)
	}
	if !report.Targets[0].Verified {
		t.Error("the target should be reported verified")
	}
	// The old key is still on the panel: the report must say so, and where, or it stays a live key.
	if f := report.Format(); !strings.Contains(f, "remove the old key ("+report.OldFingerprint+") from https://ploi.io") {
		t.Errorf("the report should say where to remove the old key:\n%s", f)
	}
}

func TestManualTargetThatFailsTheSSHProofDoesNotCommit(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	curPriv := filepath.Join(p.SSHDir, "profiles", "vcs", keyName)
	before, _ := os.ReadFile(curPriv)
	r := New(p, m, inv).WithManualStep(func(string, string, string) bool { return true })
	r.sshVerify = func(providers.Target) bool { return false }

	report, err := r.Rotate(keyName, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Committed {
		t.Fatal("a key that does not log in must not replace the working one")
	}
	if after, _ := os.ReadFile(curPriv); string(after) != string(before) {
		t.Error("the active key changed after a failed proof")
	}
}

func TestDecliningTheManualStepStopsBeforeAnySSH(t *testing.T) {
	p, m, inv, keyName := setupRotated(t)
	r := New(p, m, inv).WithManualStep(func(string, string, string) bool { return false })
	sshTried := false
	r.sshVerify = func(providers.Target) bool { sshTried = true; return true }

	report, err := r.Rotate(keyName, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Committed || sshTried {
		t.Fatalf("declined: committed=%v sshTried=%v", report.Committed, sshTried)
	}
}

// Only panel providers are logged into to prove a key: a git host refuses a shell even for a valid
// key, so an SSH "true" there proves nothing.
func TestOnlyPanelTargetsAreProvenBySSH(t *testing.T) {
	if !panelProof("panel") || panelProof("vcs") || panelProof("server") || panelProof("") {
		t.Error("the SSH proof applies to panel providers only")
	}
}
