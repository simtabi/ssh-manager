// Package scheduler installs the daily job that runs `sshmgr audit --notify`,
// ported from the platforms/*.install_scheduler layer: a launchd agent on macOS, a
// systemd --user timer (else cron) on Linux, a schtasks task on Windows. The job
// fires at 09:00 daily. Pure template/quoting helpers live here; the OS-specific
// install lives in build-tagged files.
package scheduler

import "strings"

// Label is the scheduler job label/name.
const Label = "ssh_manager.expiry"

const plistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>%LABEL%</string>
    <key>ProgramArguments</key>
    <array>
%ARGS%
    </array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
    <key>RunAtLoad</key><false/>
</dict>
</plist>
`

const serviceTmpl = `[Unit]
Description=ssh-manager key-expiry notifier

[Service]
Type=oneshot
ExecStart=%COMMAND%
`

const timerUnit = `[Unit]
Description=ssh-manager key-expiry notifier (daily)

[Timer]
OnCalendar=*-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
`

// buildPlist renders the launchd plist for a command (label + argv array).
func buildPlist(label, command string) string {
	var args []string
	for _, tok := range shlexSplit(command) {
		args = append(args, "        <string>"+xmlEscape(tok)+"</string>")
	}
	p := strings.ReplaceAll(plistTmpl, "%LABEL%", label)
	return strings.ReplaceAll(p, "%ARGS%", strings.Join(args, "\n"))
}

// buildService renders the systemd .service unit (% escaped for ExecStart).
func buildService(command string) string {
	return strings.ReplaceAll(serviceTmpl, "%COMMAND%", strings.ReplaceAll(command, "%", "%%"))
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// shlexSplit is a minimal POSIX shell-word splitter (quotes + backslash).
func shlexSplit(s string) []string {
	var args []string
	var cur strings.Builder
	inWord := false
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if quote == '"' && c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		args = append(args, cur.String())
	}
	return args
}
