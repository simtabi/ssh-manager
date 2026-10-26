// Package clipboard finds the platform's clipboard writer, for `termius keys`
// (which copies a key) and doctor (which reports when there is none).
package clipboard

import (
	"errors"
	"os"
	"os/exec"

	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
)

// Command picks the platform's clipboard writer: pbcopy on macOS,
// clip on Windows, and wl-copy, xclip or xsel on Linux and the BSDs.
func Command() (string, []string, error) {
	switch {
	case platform.IsMacOS():
		return "pbcopy", nil, nil
	case platform.IsWindows():
		return "clip", nil, nil
	}
	cands := [][]string{
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		cands = append([][]string{{"wl-copy"}}, cands...)
	}
	for _, c := range cands {
		if _, err := exec.LookPath(c[0]); err == nil {
			return c[0], c[1:], nil
		}
	}
	return "", nil, errors.New("no clipboard tool found (install wl-clipboard, xclip or xsel), or use --print")
}
