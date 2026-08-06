//go:build e2e && !windows

// Package main's end-to-end smoke, ported from .build/e2e.sh.
//
// It is tagged out of `go test ./...` on purpose: it mints six real keypairs
// with ssh-keygen and does an age round trip, which is too slow and too
// dependency-heavy for the ordinary gate. Run it with `make e2e`.
//
// Why it is Go and not shell any more: the shell version could only run on
// macOS, because four assertions used BSD `stat -f '%Lp'`, and its assertions
// rotted invisibly. When it was finally executed on this branch it was making
// four claims that the product had deliberately stopped being true - the worst
// of them asserting that `snapshots restore` brings a private key back, when
// snapshots were changed to carry no private key material at all. A shell grep
// cannot be type-checked and nothing failed at the time the behaviour changed.
//
// Windows is excluded: the mode assertions below are POSIX, and the Windows
// equivalent is internal/util/perms' ACL coverage.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// e2eHome builds the sandbox: a real binary, an isolated home, and the repo's
// shipped example manifest as the starting configuration.
func e2eHome(t *testing.T) (runner, string) {
	t.Helper()
	for _, bin := range []string{"ssh-keygen", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is required for the end-to-end flow", bin)
		}
	}
	run, home := sshmgr(t)
	if _, errOut, code := run("", "init"); code != 0 {
		t.Fatalf("init exited %d: %s", code, errOut)
	}
	// The shipped example, which is also the renderer's golden fixture - one
	// file, so the two cannot describe different trees.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "config", "manifest.json"))
	if err != nil {
		t.Fatalf("the shipped example manifest is missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "cfg", "manifest.json"), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	return run, home
}

func mustRun(t *testing.T, run runner, args ...string) string {
	t.Helper()
	out, errOut, code := run("", args...)
	if code != 0 {
		t.Fatalf("%v exited %d:\n%s%s", args, code, out, errOut)
	}
	return out
}

// TestEndToEnd walks the flow a first-time user walks, on a real binary against
// a real tree. Each subtest is named for the property it establishes.
func TestEndToEnd(t *testing.T) {
	run, home := e2eHome(t)
	ssh := filepath.Join(home, ".ssh")

	t.Run("reconcile mints a key for every profile that owns one", func(t *testing.T) {
		mustRun(t, run, "reconcile", "--dry-run")
		mustRun(t, run, "reconcile")
		for _, rel := range []string{
			"profiles/work/work_hpc-ed25519",
			"profiles/personal/personal_github-ed25519",
			"profiles/simtabi/simtabi_github-ed25519",
			"profiles/development/development_app-web-ed25519",
			"profiles/development/development_app-db-maria-ed25519",
			"profiles/development/development_app-db-psql-ed25519",
		} {
			for _, half := range []string{"", ".pub"} {
				if _, err := os.Stat(filepath.Join(ssh, rel+half)); err != nil {
					t.Errorf("%s%s was not minted: %v", rel, half, err)
				}
			}
		}
		// A profile with no hosts and no declared keys gets no directory.
		if _, err := os.Stat(filepath.Join(ssh, "profiles", "school")); err == nil {
			t.Error("a profile that owns no keys should not get a directory")
		}
	})

	t.Run("perms are load-bearing and set on create", func(t *testing.T) {
		for _, c := range []struct {
			rel  string
			want os.FileMode
		}{
			{".", 0o700},
			{"config", 0o600},
			{"known_hosts", 0o600},
			{"profiles/work/work_hpc-ed25519", 0o600},
			{"profiles/work/work_hpc-ed25519.pub", 0o644},
		} {
			fi, err := os.Stat(filepath.Join(ssh, c.rel))
			if err != nil {
				if c.rel == "known_hosts" {
					continue // only written once something is pinned
				}
				t.Errorf("%s: %v", c.rel, err)
				continue
			}
			if got := fi.Mode().Perm(); got != c.want {
				t.Errorf("%s is %04o, want %04o", c.rel, got, c.want)
			}
		}
	})

	t.Run("the rendered config matches the manifest", func(t *testing.T) {
		mustRun(t, run, "config", "check")
	})

	t.Run("two profiles on one hostname resolve to different keys", func(t *testing.T) {
		personal := mustRun(t, run, "config", "show", "github-personal")
		simtabi := mustRun(t, run, "config", "show", "github-simtabi")
		if !strings.Contains(personal, "personal/personal_github-ed25519") {
			t.Errorf("github-personal resolved to:\n%s", personal)
		}
		if !strings.Contains(simtabi, "simtabi/simtabi_github-ed25519") {
			t.Errorf("github-simtabi resolved to:\n%s", simtabi)
		}
		// The point of the whole layout: neither host is ever offered the other's
		// key, so one account's access cannot authenticate as the other.
		if strings.Contains(personal, "simtabi_github") || strings.Contains(simtabi, "personal_github") {
			t.Error("a host was offered another profile's key")
		}
	})

	t.Run("a second reconcile mints nothing and leaves the config in sync", func(t *testing.T) {
		out := mustRun(t, run, "reconcile")
		if strings.Contains(out, "minted") && !strings.Contains(out, "0") {
			t.Logf("second reconcile said:\n%s", out)
		}
		mustRun(t, run, "config", "check")
	})

	t.Run("drift inside the managed block is caught; content outside it is not", func(t *testing.T) {
		cfg := filepath.Join(ssh, "config")
		original := readFile(t, cfg)

		// Appending BELOW the end marker is foreign content, which the renderer
		// exists to preserve - editing it is not drift and must not be reported.
		if err := os.WriteFile(cfg, []byte(original+"\nHost my-own-thing\n    HostName elsewhere.example\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, code := run("", "config", "check"); code != 0 {
			t.Error("foreign content below the managed block is not drift")
		}

		// Editing INSIDE it is: the block is a pure function of the manifest, so
		// anything else there is a change the manifest does not know about.
		edited := strings.Replace(original, "User researcher", "User someone-else", 1)
		if edited == original {
			t.Fatal("the fixture no longer contains the line this test edits")
		}
		if err := os.WriteFile(cfg, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, code := run("", "config", "check"); code == 0 {
			t.Error("a hand-edited managed block should be reported as drift")
		}
		mustRun(t, run, "config", "render")
		mustRun(t, run, "config", "check")
	})

	t.Run("the query verbs report the tree they built", func(t *testing.T) {
		if out := mustRun(t, run, "list", "--type", "vcs"); !strings.Contains(out, "github-simtabi") {
			t.Errorf("list --type vcs:\n%s", out)
		}
		if out := mustRun(t, run, "list", "--tag", "db"); !strings.Contains(out, "app-db-maria") {
			t.Errorf("list --tag db:\n%s", out)
		}
		if out := mustRun(t, run, "view", "hpc"); !strings.Contains(out, "fingerprint") {
			t.Errorf("view hpc:\n%s", out)
		}
		mustRun(t, run, "expiry")
		mustRun(t, run, "audit")
		mustRun(t, run, "providers")
	})

	t.Run("validate passes, then catches a broken pair", func(t *testing.T) {
		if out := mustRun(t, run, "validate"); !strings.Contains(out, "OK") {
			t.Errorf("validate:\n%s", out)
		}
		pub := filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519.pub")
		good, err := os.ReadFile(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pub, []byte("not a key\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, code := run("", "validate", "work_hpc-ed25519"); code == 0 {
			t.Error("a malformed .pub should fail validation")
		}
		if err := os.WriteFile(pub, good, 0o644); err != nil {
			t.Fatal(err)
		}
		mustRun(t, run, "validate")
	})

	t.Run("recover emits a snippet that names authorized_keys", func(t *testing.T) {
		if out := mustRun(t, run, "recover", "work_hpc-ed25519"); !strings.Contains(out, "authorized_keys") {
			t.Errorf("recover:\n%s", out)
		}
	})

	t.Run("keygen skips existing keys and only replaces them when told twice", func(t *testing.T) {
		if out := mustRun(t, run, "keygen", "work"); !strings.Contains(strings.ToLower(out), "already exist") {
			t.Errorf("keygen should warn rather than silently skip:\n%s", out)
		}
		before := readFile(t, filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519"))

		// --force alone is refused: replacing a key destroys material with no way
		// back unless a backup can be written.
		if _, _, code := run("", "keygen", "work", "--force", "--yes"); code == 0 {
			t.Error("--force without a backup path should be refused")
		}
		if readFile(t, filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519")) != before {
			t.Fatal("the refused overwrite replaced the key anyway")
		}

		mustRun(t, run, "keygen", "work", "--force", "--yes", "--no-key-backup")
		if readFile(t, filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519")) == before {
			t.Error("--force --no-key-backup should have regenerated the key")
		}
	})

	t.Run("a mutating command leaves a snapshot that restores the config", func(t *testing.T) {
		mustRun(t, run, "config", "render")
		if out := mustRun(t, run, "snapshots", "list"); !strings.Contains(out, "ssh-") {
			t.Fatalf("no snapshot was taken:\n%s", out)
		}
		cfg := filepath.Join(ssh, "config")
		if err := os.WriteFile(cfg, []byte("# clobbered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mustRun(t, run, "snapshots", "restore", "--yes")
		if body := readFile(t, cfg); strings.Contains(body, "clobbered") {
			t.Error("restore did not bring the config back")
		}
	})

	// The property the shell harness had backwards. A snapshot is written before
	// every mutating command and several are kept, so a private key in one would
	// be a rolling plaintext archive of the user's keys. They carry none - which
	// means restore cannot bring a deleted key back, and must not pretend to.
	// The encrypted bundle is the path that does recover key material.
	t.Run("snapshots carry no private keys, so restore cannot resurrect one", func(t *testing.T) {
		key := filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519")
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		mustRun(t, run, "snapshots", "restore", "--yes")
		if _, err := os.Stat(key); err == nil {
			t.Fatal("a snapshot restored a private key; snapshots must not contain key material")
		}
		// And the tool says so rather than reporting a healthy tree.
		if _, _, code := run("", "doctor"); code == 0 {
			t.Error("doctor should not call a tree with a missing private key clean")
		}
		mustRun(t, run, "reconcile") // mint it back for the bundle round trip
	})

	t.Run("doctor is clean on a freshly reconciled tree", func(t *testing.T) {
		out, errOut, code := run("", "doctor")
		if code != 0 {
			t.Fatalf("doctor exited %d:\n%s%s", code, out, errOut)
		}
		if !strings.Contains(out, "doctor: clean") {
			t.Errorf("doctor:\n%s", out)
		}
	})

	t.Run("an age bundle round-trips the same key back", func(t *testing.T) {
		for _, bin := range []string{"age", "age-keygen"} {
			if _, err := exec.LookPath(bin); err != nil {
				t.Skipf("%s not installed; the bundle path needs it", bin)
			}
		}
		dir := t.TempDir()
		identity := filepath.Join(dir, "id.txt")
		if out, err := exec.Command("age-keygen", "-o", identity).CombinedOutput(); err != nil {
			t.Fatalf("age-keygen: %v: %s", err, out)
		}
		recipient := ""
		for _, line := range strings.Split(readFile(t, identity), "\n") {
			if rest, ok := strings.CutPrefix(line, "# public key: "); ok {
				recipient = strings.TrimSpace(rest)
			}
		}
		if recipient == "" {
			t.Fatal("could not read the recipient out of the age identity")
		}

		mustRun(t, run, "bundle", "-r", recipient, "-o", dir)
		matches, err := filepath.Glob(filepath.Join(dir, "ssh-manager-*.age"))
		if err != nil || len(matches) == 0 {
			t.Fatalf("no bundle was written: %v", err)
		}
		if head := readFile(t, matches[0]); !strings.HasPrefix(head, "age-encryption") {
			t.Error("the bundle is not an age file, so it is not encrypted")
		}

		key := filepath.Join(ssh, "profiles", "work", "work_hpc-ed25519")
		before := readFile(t, key)
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		mustRun(t, run, "restore", matches[0], "-i", identity, "--yes")
		if after := readFile(t, key); after != before {
			t.Error("restore brought back a different key; a bundle must recover the same identity")
		}
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
