// Package desktop posts a best-effort desktop notification, ported from the
// platforms/*.notify methods: terminal-notifier/osascript on macOS, notify-send on
// Linux, a PowerShell balloon on Windows. Returns false when no backend is found.
package desktop

import (
	"os/exec"
	"runtime"
	"strings"
)

// Notify posts a desktop notification. Returns true if a backend handled it.
func Notify(title, message string) bool {
	switch runtime.GOOS {
	case "darwin":
		if has("terminal-notifier") {
			_ = exec.Command("terminal-notifier", "-title", title, "-message", message).Run()
			return true
		}
		if has("osascript") {
			script := "display notification " + appleQuote(message) + " with title " + appleQuote(title)
			_ = exec.Command("osascript", "-e", script).Run()
			return true
		}
		return false
	case "linux":
		if !has("notify-send") {
			return false
		}
		body := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(message)
		_ = exec.Command("notify-send", "--", title, body).Run()
		return true
	case "windows":
		if !has("powershell") {
			return false
		}
		script := "Add-Type -AssemblyName System.Windows.Forms;" +
			"$n=New-Object System.Windows.Forms.NotifyIcon;" +
			"$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;" +
			"$n.ShowBalloonTip(10000," + psQuote(title) + "," + psQuote(message) +
			",[System.Windows.Forms.ToolTipIcon]::Info)"
		_ = exec.Command("powershell", "-NoProfile", "-Command", script).Run()
		return true
	default:
		return false
	}
}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

// appleQuote quotes a string as an AppleScript double-quoted literal.
func appleQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// psQuote quotes a string as a PowerShell single-quoted literal (doubling quotes).
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
