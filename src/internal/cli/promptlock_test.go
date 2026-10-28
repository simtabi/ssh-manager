package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// W2: a command that asks a person must not hold the lock while they read,
// because every other sshmgr command waits on it for as long as they take.
// These tests say a person is at the terminal and answer from a reader that
// notes, at the moment it is read, whether the lock is held.

type answerer struct {
	answer       string
	heldAtPrompt []bool
	during       func() // runs while the person is "reading"
	sent         bool
}

func (a *answerer) Read(b []byte) (int, error) {
	if a.sent {
		return 0, io.EOF
	}
	a.heldAtPrompt = append(a.heldAtPrompt, mutation.Held())
	if a.during != nil {
		a.during()
		a.during = nil
	}
	a.sent = true
	return copy(b, a.answer), nil
}

// asking runs a command as if a person were at the terminal.
func asking(t *testing.T, a *answerer, args ...string) (string, error) {
	t.Helper()
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = prev })
	mutation.Release()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(a)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

// promptHome is a home with a minted host, an unminted one, and a declared
// key no host uses - something for every one of these commands to act on.
func promptHome(t *testing.T) paths.Paths {
	t.Helper()
	p := editHome(t)
	run(t, "profile", "add", "work")
	run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
	run(t, "reconcile", "--yes", "--no-pin")
	run(t, "key", "add", "work", "spare")
	run(t, "host", "add", "work", "new01", "-H", "new01.example", "-u", "ops")
	mutation.Release()
	return p
}

func TestNoCommandHoldsTheLockWhileItAsks(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"reconcile", []string{"reconcile", "--no-pin"}},
		{"keygen", []string{"keygen", "work", "--no-pin"}},
		{"key delete", []string{"key", "delete", "work/spare"}},
		{"key regen-pub", []string{"key", "regen-pub", "work/work_gh-ed25519"}},
		{"host apply", []string{"host", "apply", "work", "web", "web.example", "deploy"}},
		{"clean", []string{"clean"}},
		{"import", []string{"import", "--force"}},
	}
	if len(cases) != 7 {
		t.Fatalf("%d cases; W2 names 8 commands, and deploy is phase 4's", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			promptHome(t)
			a := &answerer{answer: "y\n"}
			out, err := asking(t, a, tc.args...)
			if err != nil && !errors.Is(err, errNotClean) {
				t.Fatalf("%v: %v\n%s", tc.args, err, out)
			}
			if len(a.heldAtPrompt) == 0 {
				t.Fatalf("%v never asked:\n%s", tc.args, out)
			}
			for i, held := range a.heldAtPrompt {
				if held {
					t.Errorf("%v held the lock while asking (question %d)", tc.args, i+1)
				}
			}
			if !mutation.Held() {
				t.Errorf("%v made its change without the lock", tc.args)
			}
		})
	}
}

// A person agreed to what the question showed; if that moved while they
// read, nothing happens.
func TestAChangeWhileDecidingStopsTheCommand(t *testing.T) {
	t.Run("reconcile", func(t *testing.T) {
		p := promptHome(t)
		a := &answerer{answer: "y\n", during: func() {
			// Another command adds a host while the person reads the preview.
			port := 22
			h, u := "late.example", "ops"
			if err := editor.New(p).AddHost("work", "late", editor.HostFields{Hostname: &h, User: &u, Port: &port}); err != nil {
				t.Fatal(err)
			}
		}}
		_, err := asking(t, a, "reconcile", "--no-pin")
		if !errors.Is(err, errChanged) {
			t.Fatalf("err = %v, want errChanged", err)
		}
		if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "work_new01-ed25519")); err == nil {
			t.Error("reconcile minted a key although what it showed had changed")
		}
	})
	t.Run("host apply", func(t *testing.T) {
		p := promptHome(t)
		a := &answerer{answer: "y\n", during: func() {
			port := 22
			h, u := "web.example", "someone-else"
			if err := editor.New(p).AddHost("work", "web", editor.HostFields{Hostname: &h, User: &u, Port: &port}); err != nil {
				t.Fatal(err)
			}
		}}
		_, err := asking(t, a, "host", "apply", "work", "web", "web.example", "deploy")
		if !errors.Is(err, errChanged) {
			t.Fatalf("err = %v, want errChanged", err)
		}
		if b, _ := os.ReadFile(p.Manifest()); !strings.Contains(string(b), "someone-else") {
			t.Error("host apply overwrote the edit made while the person was deciding")
		}
	})
}

// W15: host apply asks before changing an existing profile, as every other
// manifest edit does, and a "no" changes nothing.
func TestHostApplyAsksForAnExistingProfile(t *testing.T) {
	p := promptHome(t)
	before, _ := os.ReadFile(p.Manifest())
	a := &answerer{answer: "n\n"}
	if _, err := asking(t, a, "host", "apply", "work", "web", "web.example", "deploy"); !errors.Is(err, errAborted) {
		t.Fatalf("err = %v, want errAborted", err)
	}
	if len(a.heldAtPrompt) == 0 {
		t.Fatal("host apply did not ask")
	}
	if after, _ := os.ReadFile(p.Manifest()); string(after) != string(before) {
		t.Error("a declined host apply changed the manifest")
	}
}
