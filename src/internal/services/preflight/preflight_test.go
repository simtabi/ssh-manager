package preflight

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Parity reference: python-final:src/ssh_manager/services/preflight.py. Same
// two lists, same verdict rule (ok = runtime fine AND no missing hard dep),
// same report shape.
//
// Two documented differences from the Python, both in MIGRATION_PLAN.md: the Go
// binary carries its own runtime so `python_ok` becomes a constant true (the
// actionable half - the binary scan - is unchanged), and ssh-copy-id is optional
// rather than hard on Windows, where Microsoft's OpenSSH does not ship it (D6).

// withEmptyPATH points PATH at a directory containing nothing, so every binary
// reads as missing regardless of what the machine running the test has.
func withEmptyPATH(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// withFakeBins puts executable stubs for the named binaries on PATH, and only
// those, so the scan's result is fully determined by the test.
func withFakeBins(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

func TestCheckReportsEveryMissingDependency(t *testing.T) {
	withEmptyPATH(t)
	rep := Check()

	if rep.OK() {
		t.Error("a machine with no ssh tooling at all is not ready")
	}
	if !rep.RuntimeOK {
		t.Error("a compiled Go binary always carries its runtime")
	}
	for _, want := range HardBins {
		if !contains(rep.MissingHard, want) {
			t.Errorf("missing hard dep %q not reported: %v", want, rep.MissingHard)
		}
	}
	for _, want := range OptionalBins {
		if !contains(rep.MissingOptional, want) {
			t.Errorf("missing optional dep %q not reported: %v", want, rep.MissingOptional)
		}
	}
}

// The verdict turns on hard deps only. Optional ones degrade gracefully, which
// is the entire reason for the split - a machine without `age` still works.
func TestOptionalDepsDoNotBlock(t *testing.T) {
	withFakeBins(t, HardBins...)
	rep := Check()

	if !rep.OK() {
		t.Errorf("every hard dep is present, so this should be ready: %+v", rep)
	}
	if len(rep.MissingHard) != 0 {
		t.Errorf("MissingHard = %v, want none", rep.MissingHard)
	}
	if len(rep.MissingOptional) == 0 {
		t.Error("the optional deps are absent and should still be reported")
	}
}

// One missing hard dep is enough to block, and it is named.
func TestOneMissingHardDepBlocks(t *testing.T) {
	if len(HardBins) < 2 {
		t.Skip("needs at least two hard deps to drop one")
	}
	withFakeBins(t, HardBins[1:]...)
	rep := Check()

	if rep.OK() {
		t.Error("a missing hard dep must block")
	}
	if len(rep.MissingHard) != 1 || rep.MissingHard[0] != HardBins[0] {
		t.Errorf("MissingHard = %v, want exactly %q", rep.MissingHard, HardBins[0])
	}
}

// ssh-copy-id is hard everywhere except Windows, where the platform simply does
// not ship it - requiring it there failed preflight, and doctor with it, on
// every stock machine.
func TestSSHCopyIDIsOptionalOnWindowsOnly(t *testing.T) {
	inHard, inOptional := contains(HardBins, copyID), contains(OptionalBins, copyID)
	if runtime.GOOS == "windows" {
		if inHard || !inOptional {
			t.Errorf("on Windows ssh-copy-id should be optional: hard=%v optional=%v", inHard, inOptional)
		}
		return
	}
	if !inHard || inOptional {
		t.Errorf("off Windows ssh-copy-id should be hard: hard=%v optional=%v", inHard, inOptional)
	}
}

func TestFormatNamesWhatIsWrong(t *testing.T) {
	withEmptyPATH(t)
	text := Format(Check())

	for _, want := range []string{"os:", "hard deps:", "MISSING", HardBins[0]} {
		if !strings.Contains(text, want) {
			t.Errorf("report should contain %q:\n%s", want, text)
		}
	}

	withFakeBins(t, append(append([]string{}, HardBins...), OptionalBins...)...)
	text = Format(Check())
	if strings.Contains(text, "MISSING") {
		t.Errorf("a complete machine should not report anything missing:\n%s", text)
	}
}

// The OS line carries both the GOOS token and a human name, so a bug report
// pasted from it is unambiguous.
func TestOSNameCarriesTokenAndHumanName(t *testing.T) {
	rep := Check()
	if !strings.Contains(rep.OSName, runtime.GOOS) {
		t.Errorf("OSName %q should contain the GOOS token", rep.OSName)
	}
	if !strings.Contains(rep.OSName, "(") {
		t.Errorf("OSName %q should carry a human name in parentheses", rep.OSName)
	}
	if !rep.OSFirstClass {
		t.Errorf("%s is one of the three tested platforms", runtime.GOOS)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
