package scheduler

import (
	"strings"
	"testing"
)

// Parity reference: python-final:src/ssh_manager/platforms/windows.py, covered
// by Python's tests/test_windows.py. Runs everywhere: the argv is what matters,
// and it is decidable without Windows.

func TestSchtasksRegistersADailyTask(t *testing.T) {
	argv := schtasksArgs(`"C:\Program Files\sshmgr\sshmgr.exe" audit --notify`, "ssh_manager.expiry")

	if argv[0] != "schtasks" {
		t.Fatalf("argv[0] = %q", argv[0])
	}
	// /Create is a lone flag, so the argv is not strictly paired: look each
	// flag up and take the element after it.
	value := func(flag string) string {
		for i, a := range argv {
			if a == flag && i+1 < len(argv) {
				return argv[i+1]
			}
		}
		return ""
	}
	pairs := map[string]string{
		"/TN": value("/TN"), "/TR": value("/TR"),
		"/SC": value("/SC"), "/ST": value("/ST"),
	}
	if value("/Create") == "" {
		t.Error("/Create missing: the task would not be registered")
	}
	if pairs["/TN"] != "ssh_manager.expiry" {
		t.Errorf("/TN = %q, want the label", pairs["/TN"])
	}
	if !strings.Contains(pairs["/TR"], "audit --notify") {
		t.Errorf("/TR = %q, want the command to run", pairs["/TR"])
	}
	if pairs["/SC"] != "DAILY" {
		t.Errorf("/SC = %q, want DAILY", pairs["/SC"])
	}
	if pairs["/ST"] != notifyHour {
		t.Errorf("/ST = %q, want %s", pairs["/ST"], notifyHour)
	}
}

// /F is load-bearing. Without it schtasks prompts when a task of that name
// already exists, and an install run from a script would block forever on a
// prompt nobody is there to answer. Re-registering is how an existing task gets
// upgraded, so overwriting is intended.
func TestSchtasksForcesOverwrite(t *testing.T) {
	argv := schtasksArgs("cmd", "label")
	found := false
	for _, a := range argv {
		if a == "/F" {
			found = true
		}
	}
	if !found {
		t.Error("/F missing: re-installing would hang on a confirmation prompt")
	}
}

// All three platforms notify at the same local time, so a user with more than
// one machine gets one consistent behaviour.
func TestNotifyHourMatchesTheOtherPlatforms(t *testing.T) {
	if notifyHour != "09:00" {
		t.Errorf("notifyHour = %q", notifyHour)
	}
	if !strings.Contains(timerUnit(), "09:00") {
		t.Error("the systemd timer should fire at the same hour as the Windows task")
	}
	if !strings.Contains(buildPlist("l", "c"), "<integer>9</integer>") {
		t.Error("the launchd plist should fire at the same hour as the Windows task")
	}
}
