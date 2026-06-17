//go:build windows

package scheduler

import (
	"fmt"
	"os/exec"
)

// Install registers a daily schtasks task running command at 09:00.
func Install(command, label string) error {
	if _, err := exec.LookPath("schtasks"); err != nil {
		return fmt.Errorf("schtasks not found: schtasks ships with Windows")
	}
	return exec.Command("schtasks", "/Create", "/TN", label, "/TR", command,
		"/SC", "DAILY", "/ST", "09:00", "/F").Run()
}
