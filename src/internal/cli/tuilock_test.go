package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
)

// lockWatch notes, at every menu prompt and every confirmation, whether the
// lock is held, and can change the home while the person is deciding.
type lockWatch struct {
	*scriptPrompter
	atMenu, atConfirm []bool
	during            func()
}

func (w *lockWatch) Line(msg string) (string, bool) {
	w.atMenu = append(w.atMenu, mutation.Held())
	return w.scriptPrompter.Line(msg)
}

func (w *lockWatch) Confirm(msg string) bool {
	w.atConfirm = append(w.atConfirm, mutation.Held())
	if w.during != nil {
		w.during()
		w.during = nil
	}
	return w.scriptPrompter.Confirm(msg)
}

func watched(t *testing.T, answers ...string) (*tui, *lockWatch, *bytes.Buffer) {
	t.Helper()
	t.Setenv("SSH_MANAGER_AUTO_PIN", "0")
	tt, buf := tuiWith(t)
	w := &lockWatch{scriptPrompter: &scriptPrompter{answers: answers, confirm: true}}
	tt.pr = w
	return tt, w, buf
}

// A menu session holds the lock only while an action runs: not while it shows
// the menu, and not while Reconcile asks whether to apply.
func TestTheTUIHoldsTheLockOnlyWhileAnActionRuns(t *testing.T) {
	tt, w, buf := watched(t, "reconcile", "reconcile", "q")
	tt.run()
	if len(w.atMenu) != 3 || len(w.atConfirm) != 2 {
		t.Fatalf("menu prompts %v, confirmations %v: the session did not run both reconciles", w.atMenu, w.atConfirm)
	}
	for i, held := range w.atMenu {
		if held {
			t.Errorf("menu prompt %d: the lock is held between actions", i+1)
		}
	}
	for i, held := range w.atConfirm {
		if held {
			t.Errorf("confirmation %d: the lock is held while the person decides", i+1)
		}
	}
	if !strings.Contains(buf.String(), "minted") {
		t.Errorf("the first reconcile minted nothing:\n%s", buf)
	}
}

// When the manifest moves while Reconcile is asking, it stops, changes
// nothing, and the edit made meanwhile survives.
func TestTUIReconcileStopsWhenTheManifestMoves(t *testing.T) {
	tt, w, buf := watched(t, "reconcile", "q")
	w.during = func() {
		u, h := "ops", "db.example"
		if err := editor.New(tt.p).AddHost("work", "db", editor.HostFields{Hostname: &h, User: &u}); err != nil {
			t.Fatal(err)
		}
	}
	tt.run()
	out := buf.String()
	if !strings.Contains(out, errChanged.Error()) {
		t.Fatalf("no stop on a moved manifest:\n%s", out)
	}
	m, err := manifest.Load(tt.p.Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Profiles["work"].Hosts) != 2 {
		t.Error("the edit made while deciding was lost")
	}
	if _, err := os.Stat(filepath.Join(tt.p.SSHDir, "profiles", "work", "work_gh-ed25519")); err == nil {
		t.Error("reconcile minted a key after the manifest moved")
	}
}
