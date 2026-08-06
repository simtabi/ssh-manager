package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/notifier"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/scheduler"
)

// newNotifyCmd is the native notify verb group: install the scheduled expiry
// notifier, or fire a test desktop notification.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Manage the scheduled expiry notifier",
	}

	var installYes bool
	install := &cobra.Command{
		Use:   "install",
		Short: "Install the scheduled expiry notifier",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			if err := refuseInDevMode(p, "notify install",
				"it registers a job with launchd, systemd or schtasks, which is "+
					"machine-wide and outlives the sandbox"); err != nil {
				return err
			}
			command := schedulerExe() + " audit --notify"
			if err := confirmChange(c,
				"notify install registers a scheduled job with this system's scheduler:\n  "+
					command, installYes); err != nil {
				return err
			}
			if err := scheduler.Install(command, scheduler.Label); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "installed scheduled notifier: %s\n", command)
			return nil
		},
	}
	install.Flags().BoolVarP(&installYes, "yes", "y", false, "install without confirming (implied when there is no terminal)")
	cmd.AddCommand(install)

	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Fire a test notification",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if notifier.New(p, m).Test() {
				_, _ = fmt.Fprintln(c.OutOrStdout(), "sent a test desktop notification.")
			} else {
				_, _ = fmt.Fprintln(c.ErrOrStderr(), "no notification backend found (install notify-send / terminal-notifier).")
			}
			return nil
		},
	})

	return cmd
}

// schedulerExe is the quoted invocation for the scheduled job. The sshmgr on PATH
// if present, else this binary; quoted so a path with spaces stays one token
// (double quotes on Windows, shell-quote on POSIX). Mirrors facade._scheduler_exe.
func schedulerExe() string {
	exe, err := exec.LookPath("sshmgr")
	if err != nil {
		if self, e := os.Executable(); e == nil {
			exe = self
		} else {
			exe = "sshmgr"
		}
	}
	if platform.IsWindows() {
		return `"` + exe + `"`
	}
	return shellQuote(exe)
}

// shellQuote quotes a string for POSIX shells (shlex.quote): bare if safe, else
// single-quoted with embedded quotes escaped.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\$`&|;<>()*?[]{}~#!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
