package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunForwardsArgsAndExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-engine helper is a POSIX shell script")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	engineBin := filepath.Join(dir, "engine")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nexit 7\n"
	if err := os.WriteFile(engineBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_MANAGER_ENGINE", engineBin)

	code, err := Run([]string{"reconcile", "--dry-run"})
	if err != nil {
		t.Fatalf("Run errored: %v", err)
	}
	if code != 7 {
		t.Fatalf("exit code = %d, want 7 (engine exit must propagate)", code)
	}
	got, _ := os.ReadFile(argsFile)
	if string(got) != "reconcile\n--dry-run\n" {
		t.Fatalf("engine received args %q, want reconcile + --dry-run", got)
	}
}

func TestRunNoEngineIsError(t *testing.T) {
	t.Setenv("SSH_MANAGER_ENGINE", "")
	if _, err := Run([]string{"doctor"}); err == nil {
		t.Fatal("expected an error when no engine is configured")
	}
}
