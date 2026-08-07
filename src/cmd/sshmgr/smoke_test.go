package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Ports the exit-code half of v1's smoke tests, and closes the
// gap exit_test.go names in its own header: "Go cannot assert the code without
// spawning a process". It can - it just has to build the binary and run it.
//
// Everything else in the suite tests packages. This tests the program: that
// cmd/sshmgr links, that the cobra tree is reachable through it, and that the
// exit codes a script or a cron job sees are the documented ones. The contract
// is v1's CLI - 0 on success (:147 doctor's
// `0 if report.ok else 1`), 1 on everything else (:59-62 _fail), 1 and silent on
// a declined confirmation (:343-344).

// runner runs the built binary against an isolated home.
type runner func(stdin string, args ...string) (stdout, stderr string, code int)

// sshmgr builds the binary once and returns a runner over an isolated home,
// plus that home, so a test can inspect the tree the binary produced.
func sshmgr(t *testing.T) (runner, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain to build with")
	}
	bin := filepath.Join(t.TempDir(), "sshmgr")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/sshmgr: %v\n%s", err, out)
	}

	home := t.TempDir()
	cfg := filepath.Join(home, "cfg")
	env := append(os.Environ(),
		"HOME="+home,
		"USERPROFILE="+home,
		"SSH_MANAGER_HOME="+cfg,
		"SSH_MANAGER_AUTO_PIN=0", // no network reach during a test
	)
	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out, errBuf strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		err := cmd.Run()
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("running %v: %v", args, err)
			}
			code = ee.ExitCode()
		}
		return out.String(), errBuf.String(), code
	}
	return run, home
}

func TestTheBinaryReportsItsVersionAndExitsZero(t *testing.T) {
	run, _ := sshmgr(t)

	for _, args := range [][]string{{"--version"}, {"version"}} {
		out, errOut, code := run("", args...)
		if code != 0 {
			t.Errorf("%v exited %d: %s%s", args, code, out, errOut)
		}
		if !strings.Contains(out, "sshmgr") || len(strings.TrimSpace(out)) < len("sshmgr 0") {
			t.Errorf("%v printed %q, want a version line", args, out)
		}
	}

	// No arguments opens the TUI on a terminal. There is no terminal here - the
	// runner gives the child a pipe - so it falls back to help, which is the
	// behaviour a script or a CI job gets and the one worth pinning: a TUI
	// reading from a pipe would consume whatever is on it as menu answers.
	out, _, code := run("")
	if code != 0 {
		t.Errorf("the bare command exited %d, want 0 with help", code)
	}
	for _, verb := range []string{"reconcile", "doctor", "rotate", "bundle"} {
		if !strings.Contains(out, verb) {
			t.Errorf("help does not mention %q:\n%s", verb, out)
		}
	}
}

// Every failure is exit 1 - there is no second failure code to distinguish, and
// a script only needs to know whether it worked.
func TestFailuresExitOneAndExplainThemselvesOnStderr(t *testing.T) {
	run, _ := sshmgr(t)

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"nosuchcommand"}, "unknown command"},
		{[]string{"view", "nope"}, "manifest not found"}, // no home yet
	} {
		stdout, stderr, code := run("", tc.args...)
		if code != 1 {
			t.Errorf("%v exited %d, want 1", tc.args, code)
		}
		if !strings.Contains(stderr, tc.want) {
			t.Errorf("%v stderr = %q, want it to mention %q", tc.args, stderr, tc.want)
		}
		// Errors go to stderr so `sshmgr view x > file` leaves the file empty
		// rather than containing an error message a later step would parse.
		if strings.Contains(stdout, tc.want) {
			t.Errorf("%v wrote its error to stdout:\n%s", tc.args, stdout)
		}
		if !strings.HasPrefix(strings.TrimSpace(stderr), "sshmgr:") {
			t.Errorf("%v stderr = %q, want the tool to name itself", tc.args, stderr)
		}
	}
}

// The whole first-run path, as a user would take it, through the real binary.
func TestInitReconcileDoctorRunEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	run, home := sshmgr(t)

	for _, args := range [][]string{
		{"init"},
		{"profile", "add", "work"},
		{"host", "add", "work", "gh", "-H", "github.com", "-u", "git"},
		{"reconcile"},
	} {
		out, errOut, code := run("", args...)
		if code != 0 {
			t.Fatalf("%v exited %d:\n%s%s", args, code, out, errOut)
		}
	}

	// doctor is the one command whose exit code is a verdict rather than a
	// success/failure: 0 when the tree is clean, 1 when it is not.
	out, errOut, code := run("", "doctor")
	if code != 0 {
		t.Fatalf("doctor on a freshly reconciled tree exited %d:\n%s%s", code, out, errOut)
	}

	if runtime.GOOS != "windows" {
		key := filepath.Join(home, ".ssh", "profiles", "work", "work_gh-ed25519")
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		out, _, code = run("", "doctor")
		if code != 1 {
			t.Errorf("doctor exited %d over a world-readable private key, want 1:\n%s", code, out)
		}
		// And --fix repairs it, so the next run is clean again.
		if _, errOut, code := run("", "doctor", "--fix"); code != 0 {
			t.Errorf("doctor --fix exited %d: %s", code, errOut)
		}
		if _, _, code := run("", "doctor"); code != 0 {
			t.Error("doctor still fails after its own --fix")
		}
	}
}

// A declined confirmation exits 1 like any other failure, but prints nothing of
// its own: the user just answered the question, and "sshmgr: aborted" under
// their own "n" reads like a fault rather than the answer they gave.
func TestADeclinedConfirmationExitsOneAndSaysNothingExtra(t *testing.T) {
	run, _ := sshmgr(t)
	if _, errOut, code := run("", "init"); code != 0 {
		t.Fatalf("init exited %d: %s", code, errOut)
	}
	if _, errOut, code := run("", "profile", "add", "tp"); code != 0 {
		t.Fatalf("profile add exited %d: %s", code, errOut)
	}

	stdout, stderr, code := run("n\n", "profile", "delete", "tp")
	if code != 1 {
		t.Errorf("declining exited %d, want 1", code)
	}
	if strings.Contains(stderr, "sshmgr:") {
		t.Errorf("an abort printed an error line: %q", stderr)
	}
	if !strings.Contains(stdout, "[y/N]") {
		t.Errorf("the prompt was not shown:\n%s", stdout)
	}
	// Nothing was deleted.
	list, _, _ := run("", "list")
	if !strings.Contains(list, "tp") {
		t.Errorf("the declined profile is gone:\n%s", list)
	}
}

// `doctor --json` is the scripting surface, so what matters is that it parses
// and carries the keys a script would index. This replaces the one assertion in
// .build/feature-check.sh that shelled out to an interpreter to validate it - the last
// an executing interpreter anywhere in this repo's CI.
func TestDoctorJSONIsMachineReadable(t *testing.T) {
	run, _ := sshmgr(t)
	if _, errOut, code := run("", "init"); code != 0 {
		t.Fatalf("init exited %d: %s", code, errOut)
	}

	out, errOut, code := run("", "doctor", "--json")
	if code != 0 && code != 1 { // 1 is a verdict, not a failure to produce output
		t.Fatalf("doctor --json exited %d: %s", code, errOut)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("doctor --json did not produce parseable JSON: %v\n%s", err, out)
	}
	// The fields a script indexes. Nothing asserted their presence before - only
	// that the whole document parsed, which a bare `{}` also does.
	for _, key := range []string{"home", "ssh_dir", "perm_issues", "orphan_keys",
		"duplicate_keys", "unpinned_hosts", "alias_collisions", "old_keys"} {
		if _, ok := report[key]; !ok {
			t.Errorf("doctor --json is missing %q; a script reading it would get nil", key)
		}
	}
	// Empty collections serialize as [] and {}, never null - a consumer should
	// not have to distinguish "none" from "absent".
	for _, key := range []string{"perm_issues", "orphan_keys", "duplicate_keys"} {
		if _, ok := report[key].([]any); !ok {
			t.Errorf("%s is %T, want a JSON array even when empty", key, report[key])
		}
	}
	// Errors never contaminate the document.
	if strings.Contains(out, "sshmgr:") {
		t.Errorf("a diagnostic leaked into the JSON payload:\n%s", out)
	}
}
