//go:build !linux && !darwin && !windows

package platform

// StdinIsTerminal reports whether standard input is a terminal. Platforms
// outside the released set (linux, darwin, windows) have no terminal handling,
// so callers fall back to reading piped input.
func StdinIsTerminal() bool { return false }

// ReadSecret always fails on unsupported platforms rather than reading with echo
// left on, so a passphrase can never be silently displayed.
func ReadSecret(string) (string, error) { return "", ErrNotATerminal }
