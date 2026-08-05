package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI half of the command surface, ported from .build/feature-check.sh.
//
// Each service underneath these verbs is verified in its own package. What is
// unproven at that level, and what these assert, is the wiring: that the verb
// exists, that its flags reach the service, that it refuses what it should, and
// that a failure returns rather than exiting. Subtests are named for their
// matrix row, so `go test -run 'TestCommandSurface/C05'` prints exactly the
// evidence for one row.
//
// Do not add t.Parallel(): editHome uses t.Setenv, which panics in a parallel
// test. The suite is fast enough without it.
//
// A row that needs more than a few assertions, or a fixture of its own, gets its
// own test in its own file - as show_test.go and key_test.go already do. This
// table is for the uniform cases, not a universal solvent.

func needBin(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s is not installed", n)
		}
	}
}

// C05 `init [--force] [--backup]`
func TestCommandSurfaceC05Init(t *testing.T) {
	t.Run("C05/seeds the home and says what it created", func(t *testing.T) {
		p := editHome(t)
		out := run(t, "init")
		for _, want := range []string{"manifest.json", "inventory.json", ".env"} {
			if !strings.Contains(out, want) {
				t.Errorf("init did not report %s:\n%s", want, out)
			}
		}
		for _, d := range []string{"log", "snapshots", ".state", "dist"} {
			if fi, err := os.Stat(filepath.Join(p.ConfigDir, d)); err != nil || !fi.IsDir() {
				t.Errorf("init did not create %s/: %v", d, err)
			}
		}
		// providers.json is deliberately NOT seeded: the full catalog ships in the
		// binary, and a user file exists only to override it.
		if _, err := os.Stat(p.Providers()); err == nil {
			t.Error("init seeded providers.json; the shipped catalog should be used instead")
		}
	})

	t.Run("C05/a second run leaves what is already there", func(t *testing.T) {
		p := editHome(t)
		run(t, "init")
		mine := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{}}`
		if err := os.WriteFile(p.Manifest(), []byte(mine), 0o600); err != nil {
			t.Fatal(err)
		}
		out := run(t, "init")
		if !strings.Contains(strings.ToLower(out), "exists") {
			t.Errorf("init should say what it left alone:\n%s", out)
		}
		if got, _ := os.ReadFile(p.Manifest()); string(got) != mine {
			t.Error("a plain init overwrote an existing manifest")
		}
	})

	t.Run("C05/--force --backup keeps the manifest it replaces", func(t *testing.T) {
		p := editHome(t)
		run(t, "init")
		mine := `{"version":1,"defaults":{"key_type":"ed25519"},"profiles":{}}`
		if err := os.WriteFile(p.Manifest(), []byte(mine), 0o600); err != nil {
			t.Fatal(err)
		}
		run(t, "init", "--force", "--backup")

		saved, err := filepath.Glob(filepath.Join(p.StateDir(), "init-backup-*", "manifest.json"))
		if err != nil || len(saved) == 0 {
			t.Fatalf("--backup wrote no backup: %v", err)
		}
		if got, _ := os.ReadFile(saved[0]); string(got) != mine {
			t.Error("the backup does not hold the manifest that was replaced")
		}
	})

	t.Run("C05/--force without --backup leaves no backup directory", func(t *testing.T) {
		p := editHome(t)
		run(t, "init")
		run(t, "init", "--force")
		if dirs, _ := filepath.Glob(filepath.Join(p.StateDir(), "init-backup-*")); len(dirs) != 0 {
			t.Errorf("--force alone should not write a backup: %v", dirs)
		}
	})
}

// C06 `migrate` (config home)
func TestCommandSurfaceC06Migrate(t *testing.T) {
	t.Run("C06/with no legacy home it reports that and changes nothing", func(t *testing.T) {
		editHome(t)
		out := run(t, "migrate")
		if !strings.Contains(strings.ToLower(out), "no legacy") {
			t.Errorf("migrate should name what it looked for:\n%s", out)
		}
	})
}

// C07 `import`
func TestCommandSurfaceC07Import(t *testing.T) {
	t.Run("C07/onboards an existing ssh config into the manifest", func(t *testing.T) {
		needBin(t, "ssh-keygen")
		p := editHome(t)
		sshDir := filepath.Join(p.SSHDir)
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatal(err)
		}
		key := filepath.Join(sshDir, "id_demo")
		if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "demo", "-f", key).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v: %s", err, out)
		}
		cfg := filepath.Join(sshDir, "config")
		body := "Host demo\n    HostName demo.example\n    User git\n    IdentityFile " + key + "\n"
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		out := run(t, "import", cfg)
		if !strings.Contains(out, "import") {
			t.Errorf("import printed no summary:\n%s", out)
		}
		if listing := run(t, "list"); !strings.Contains(listing, "demo") {
			t.Errorf("the imported host is not in the manifest:\n%s", listing)
		}
	})

	t.Run("C07/a config that is not there is an error, not an empty import", func(t *testing.T) {
		editHome(t)
		if _, err := runErr(t, "import", filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("importing a missing config should fail")
		}
	})
}

// C14 `load <profile>`
func TestCommandSurfaceC14Load(t *testing.T) {
	t.Run("C14/an unknown profile is refused before the agent is touched", func(t *testing.T) {
		editHome(t)
		t.Setenv("PATH", t.TempDir()) // no ssh-add reachable
		if _, err := runErr(t, "load", "no-such-profile"); err == nil {
			t.Error("loading an unknown profile should fail")
		}
	})
}

// C29 `knownhosts init|pin`
func TestCommandSurfaceC29KnownHosts(t *testing.T) {
	t.Run("C29/init creates the single trust store owner-only", func(t *testing.T) {
		p := editHome(t)
		run(t, "profile", "add", "work")
		// A closed loopback port, not a real host: pinning reaches for
		// ssh-keyscan, and a suite that makes outbound connections hangs on an
		// offline runner and flakes on a slow one.
		run(t, "host", "add", "work", "gh", "-H", "127.0.0.1", "-u", "git", "-p", "1")
		// It takes a profile or --all; there is no "everything by default", so a
		// bare invocation cannot silently pin a tree the user did not name.
		if _, err := runErr(t, "knownhosts", "init"); err == nil {
			t.Error("knownhosts init with no target should say what it needs")
		}
		run(t, "knownhosts", "init", "--all")

		store := filepath.Join(p.SSHDir, "known_hosts")
		fi, err := os.Stat(store)
		if err != nil {
			t.Fatalf("no trust store was created: %v", err)
		}
		// 0600, not 0644: the store is an inventory of every host the user talks
		// to, which is also why the names in it are hashed.
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("known_hosts is %04o, want 0600", mode)
		}
		// One store, not one per profile - the v2 layout change.
		if _, err := os.Stat(filepath.Join(p.SSHDir, "profiles", "work", "known_hosts")); err == nil {
			t.Error("a per-profile trust store was created; there is one store now")
		}
	})
}

// C15/C16 `rotate` / `rollback`
func TestCommandSurfaceC15RotateC16Rollback(t *testing.T) {
	t.Run("C15/rotating a key that does not exist is refused", func(t *testing.T) {
		editHome(t)
		if _, err := runErr(t, "rotate", "no/such-key", "--yes"); err == nil {
			t.Error("rotating an unknown key should fail")
		}
	})

	t.Run("C16/rolling back with no archived predecessor is refused", func(t *testing.T) {
		needBin(t, "ssh-keygen")
		editHome(t)
		run(t, "profile", "add", "work")
		run(t, "host", "add", "work", "gh", "-H", "github.com", "-u", "git")
		run(t, "reconcile")
		// Nothing has been rotated, so there is no old/ copy to return to.
		if _, err := runErr(t, "rollback", "work/work_gh-ed25519", "--yes"); err == nil {
			t.Error("rollback with no predecessor should fail rather than no-op silently")
		}
	})
}

// C31 `show` — the reconciliation view. Its own file covers the output; this
// covers the wiring and the refusal.
func TestCommandSurfaceC31Show(t *testing.T) {
	t.Run("C31/an unknown selector names what it could not find", func(t *testing.T) {
		editHome(t)
		out, err := runErr(t, "show", "nothing-by-this-name")
		if err == nil {
			t.Fatal("show should fail on an unknown selector")
		}
		if !strings.Contains(err.Error()+out, "nothing-by-this-name") {
			t.Errorf("the error should quote what was asked for: %v\n%s", err, out)
		}
	})
}

// Arity is part of the contract: a verb that silently ignores an extra argument
// will do the wrong thing for a mistyped command rather than saying so.
func TestVerbsRejectExtraArguments(t *testing.T) {
	editHome(t)
	for _, args := range [][]string{
		{"version", "extra"},
		{"expiry", "extra"},
		{"providers", "extra"},
		{"diff", "extra"},
		{"migrate", "extra"},
	} {
		if _, err := runErr(t, args...); err == nil {
			t.Errorf("%v should be rejected: the verb takes no argument", args)
		}
	}
}
