package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/internal/core/manifest"
	"github.com/simtabi/ssh-manager/internal/services/notifier"
	"github.com/simtabi/ssh-manager/internal/util/paths"
	"github.com/simtabi/ssh-manager/internal/util/scheduler"
)

// newNotifyCmd is the native notify verb group: install the scheduled expiry
// notifier, or fire a test desktop notification.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Manage the scheduled expiry notifier",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install the scheduled expiry notifier",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			command := schedulerExe() + " audit --notify"
			if err := scheduler.Install(command, scheduler.Label); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "installed scheduled notifier: %s\n", command)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Fire a test notification",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p := paths.Resolve(nil, "", "")
			m, err := manifest.Load(p.Manifest())
			if err != nil {
				return err
			}
			if notifier.New(p, m.Defaults).Test() {
				fmt.Fprintln(c.OutOrStdout(), "sent a test desktop notification.")
			} else {
				fmt.Fprintln(os.Stderr, "no notification backend found (install notify-send / terminal-notifier).")
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
	if runtime.GOOS == "windows" {
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
