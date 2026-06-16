// Package engine is the boundary to the ssh-manager engine that does the actual
// work. During the Go migration the engine is the v1 Python implementation
// (frozen into the binary for releases, or pointed at via $SSH_MANAGER_ENGINE in
// development). As modules are ported to Go they stop going through here.
package engine

import (
	"errors"
	"os"
	"os/exec"
)

// ErrNoEngine is returned when no ssh-manager engine can be located.
var ErrNoEngine = errors.New(
	"ssh-manager engine not found: set $SSH_MANAGER_ENGINE to the engine " +
		"executable, or use a release build with the engine bundled")

// resolve returns the engine executable path. Resolution order:
//  1. $SSH_MANAGER_ENGINE (an executable) - dev override and the path the
//     embedded-engine extractor sets at runtime.
//  2. the bundled engine (wired in by the go:embed build; see embed_*.go).
func resolve() (string, error) {
	if p := os.Getenv("SSH_MANAGER_ENGINE"); p != "" {
		return p, nil
	}
	if p := bundledEngine(); p != "" {
		return p, nil
	}
	return "", ErrNoEngine
}

// Run executes the engine with args, wiring stdio straight through, and returns
// the engine's exit code. A non-launch failure (engine missing, not executable)
// is returned as an error; a non-zero engine exit is returned as the code with a
// nil error so the caller can propagate it.
func Run(args []string) (code int, err error) {
	bin, err := resolve()
	if err != nil {
		return 1, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
