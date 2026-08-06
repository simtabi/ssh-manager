package desktop

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// L2/L3's notification path. Notify picks its backend with exec.LookPath, so a
// stub first on PATH makes both outcomes decidable without a desktop session -
// which is the reason this package had no test file at all until now.

func stubBackend(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "argv.txt")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]\\n' \"$a\" >> " + log + "; done\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

// The contract every caller relies on: false means nothing was delivered, so
// the notifier can decline to spend its cadence on a message nobody saw.
func TestNotifyReportsFalseWhenNoBackendExists(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if Notify("title", "message") {
		t.Error("with nothing on PATH, Notify must report that it delivered nothing")
	}
}

func TestNotifyUsesThePlatformsBackend(t *testing.T) {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "terminal-notifier"
	case "linux":
		name = "notify-send"
	default:
		t.Skip("no scriptable backend on " + runtime.GOOS)
	}
	log := stubBackend(t, name)

	if !Notify("ssh-manager", "a key is due") {
		t.Fatal("Notify should report success when a backend handled it")
	}
	argv, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the backend was not invoked: %v", err)
	}
	for _, want := range []string{"ssh-manager", "a key is due"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("argv = %q, want it to carry %q", argv, want)
		}
	}
}

// Quoting is the part that can go wrong silently. The title and body are the
// tool's own text plus a key name, and a key name can contain a quote or an
// apostrophe; on macOS both are interpolated into an AppleScript literal and on
// Windows into a PowerShell one. A broken escape either drops the notification
// or runs whatever follows.
func TestQuotingSurvivesCharactersThatWouldCloseTheLiteral(t *testing.T) {
	for _, in := range []string{`plain`, `it's`, `say "hi"`, `back\slash`, `mixed "and" it's`} {
		apple := appleQuote(in)
		if !strings.HasPrefix(apple, `"`) || !strings.HasSuffix(apple, `"`) {
			t.Errorf("appleQuote(%q) = %s, want a double-quoted literal", in, apple)
		}
		// Every inner quote and backslash escaped, so the literal cannot end early.
		inner := apple[1 : len(apple)-1]
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' {
				i++ // skip what it escapes
				continue
			}
			if inner[i] == '"' {
				t.Errorf("appleQuote(%q) = %s: an unescaped quote closes the literal", in, apple)
				break
			}
		}

		ps := psQuote(in)
		if !strings.HasPrefix(ps, "'") || !strings.HasSuffix(ps, "'") {
			t.Errorf("psQuote(%q) = %s, want a single-quoted literal", in, ps)
		}
		// PowerShell escapes a quote by doubling it, so every one inside must be
		// part of a pair.
		body := ps[1 : len(ps)-1]
		for i := 0; i < len(body); i++ {
			if body[i] != '\'' {
				continue
			}
			if i+1 >= len(body) || body[i+1] != '\'' {
				t.Errorf("psQuote(%q) = %s: a lone quote closes the literal", in, ps)
				break
			}
			i++
		}
	}
}
