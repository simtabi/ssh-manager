//go:build windows

package scheduler

import (
	"fmt"
	"os/exec"
)

// Install registers the daily notifier task. The argv comes from
// schtasksArgs in windows_task.go, which is compiled and tested everywhere;
// this file is only the part that runs it.
func Install(command, label string) error {
	if _, err := exec.LookPath("schtasks"); err != nil {
		return fmt.Errorf("schtasks not found: schtasks ships with Windows")
	}
	argv := schtasksArgs(command, label)
	return exec.Command(argv[0], argv[1:]...).Run()
}
