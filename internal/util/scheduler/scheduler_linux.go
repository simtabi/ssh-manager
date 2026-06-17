//go:build linux

package scheduler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Install registers a daily job: a systemd --user timer if available, else cron.
func Install(command, label string) error {
	switch {
	case has("systemctl"):
		return installSystemd(command, label)
	case has("crontab"):
		return installCron(command, label)
	default:
		return fmt.Errorf("no scheduler found: install systemd (systemctl) or cron (crontab)")
	}
}

func systemdUserDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user")
}

func installSystemd(command, label string) error {
	dir := systemdUserDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, label+".service"), []byte(buildService(command)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, label+".timer"), []byte(timerUnit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	if err := exec.Command("systemctl", "--user", "enable", "--now", label+".timer").Run(); err != nil {
		return err
	}
	removeCron(label) // don't let a stale cron entry double-fire
	return nil
}

func installCron(command, label string) error {
	removeSystemd(label)
	marker := "# " + label
	var kept []string
	if out, err := exec.Command("crontab", "-l").Output(); err == nil {
		for _, ln := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			if ln != "" && !strings.Contains(ln, marker) {
				kept = append(kept, ln)
			}
		}
	}
	escaped := strings.ReplaceAll(command, "%", `\%`)
	kept = append(kept, fmt.Sprintf("0 9 * * * %s %s", escaped, marker))
	return crontabIn(strings.Join(kept, "\n") + "\n")
}

func removeCron(label string) {
	if !has("crontab") {
		return
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return
	}
	marker := "# " + label
	var kept []string
	for _, ln := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if ln != "" && !strings.Contains(ln, marker) {
			kept = append(kept, ln)
		}
	}
	body := ""
	if len(kept) > 0 {
		body = strings.Join(kept, "\n") + "\n"
	}
	_ = crontabIn(body)
}

func removeSystemd(label string) {
	if has("systemctl") {
		_ = exec.Command("systemctl", "--user", "disable", "--now", label+".timer").Run()
	}
	dir := systemdUserDir()
	_ = os.Remove(filepath.Join(dir, label+".service"))
	_ = os.Remove(filepath.Join(dir, label+".timer"))
}

func crontabIn(body string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(body)
	return cmd.Run()
}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }
