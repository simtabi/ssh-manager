//go:build darwin

package scheduler

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Install writes a launchd agent that runs command daily at 09:00 and (re)loads it.
func Install(command, label string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dest := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dest, []byte(buildPlist(label, command)), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "unload", dest).Run() // ignore (first install)
	return exec.Command("launchctl", "load", dest).Run()
}
