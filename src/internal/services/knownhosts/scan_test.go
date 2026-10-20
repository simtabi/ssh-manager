package knownhosts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeKeyscan puts an ssh-keyscan on PATH that prints out, or no ssh-keyscan at all when out is nil.
func fakeKeyscan(t *testing.T, out *string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	if out != nil {
		body := strings.ReplaceAll(*out, "'", `'\''`)
		script := "#!/bin/sh\nprintf '%s' '" + body + "'\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "ssh-keyscan"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

func str(s string) *string { return &s }

// A reachable host that serves no SSH key (a web server on 443, say) used to come back as an empty
// slice, and `knownhosts pin` reported "pinned 0 host key(s)" and exited 0.
func TestScanCheckedSaysWhyNothingCameBack(t *testing.T) {
	fakeKeyscan(t, str(""))
	keys, err := New(t.TempDir()).ScanChecked("sc.example.edu", 443)
	if err == nil {
		t.Fatalf("no keys and no error: %v", keys)
	}
	for _, want := range []string{"sc.example.edu:443", "no SSH host key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestScanCheckedNamesAMissingKeyscan(t *testing.T) {
	fakeKeyscan(t, nil)
	_, err := New(t.TempDir()).ScanChecked("github.com", 22)
	if err == nil || !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Fatalf("err=%v, want one naming ssh-keyscan", err)
	}
}

func TestScanCheckedReturnsKeys(t *testing.T) {
	fakeKeyscan(t, str("# github.com:22 SSH-2.0\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"))
	keys, err := New(t.TempDir()).ScanChecked("github.com", 22)
	if err != nil || len(keys) != 1 || keys[0].Keytype != "ssh-ed25519" {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
}

// Scan keeps its old contract for its existing callers: no error, just whatever came back.
func TestScanStillReturnsEmptyWithoutError(t *testing.T) {
	fakeKeyscan(t, str(""))
	if keys := New(t.TempDir()).Scan("h", 22); len(keys) != 0 {
		t.Fatalf("keys=%v", keys)
	}
}
