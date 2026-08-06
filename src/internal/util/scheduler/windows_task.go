package scheduler

// The Windows task definition, kept out of the build-tagged file that runs it,
// so the argv can be checked on any machine rather than only on Windows.

// notifyHour is when the daily expiry check runs. All three platforms read it
// from here: a user with a Mac and a Linux box should get the same behaviour,
// and the hour was previously a literal repeated behind three build tags, where
// no test could see more than one of them at a time.
const notifyHour = "09:00"

// timerUnit is the systemd timer that drives the notifier, built from
// notifyHour so it cannot drift from the other two platforms.
func timerUnit() string {
	return `[Unit]
Description=ssh-manager key-expiry notifier (daily)

[Timer]
OnCalendar=*-*-* ` + notifyHour + `:00
Persistent=true

[Install]
WantedBy=timers.target
`
}

// schtasksArgs is the argv that registers the daily notifier task.
//
// /F is load-bearing: without it schtasks prompts for confirmation when a task
// of that name already exists, and a scheduled install would block forever on a
// prompt nobody is there to answer. Re-registering is how the command upgrades
// an existing task, so overwriting is the intended behaviour, not a shortcut.
func schtasksArgs(command, label string) []string {
	return []string{"schtasks", "/Create", "/TN", label, "/TR", command,
		"/SC", "DAILY", "/ST", notifyHour, "/F"}
}
