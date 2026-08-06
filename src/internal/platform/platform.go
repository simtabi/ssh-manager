// Package platform isolates the OS-specific behaviour sshmgr needs, so the rest
// of the tree can stay free of runtime.GOOS branches: terminal handling for
// reading secrets without echoing them (here), and the OS predicates every other
// package asks its questions through (os.go).
//
// The one deliberate exception is util/desktop, which dispatches to a different
// notification backend per OS. That is a self-contained implementation choice
// rather than a predicate leaking across the tree, so it keeps its own switch.
package platform

import (
	"errors"
	"io"
)

// ErrNotATerminal is returned by ReadSecret when standard input is not a
// terminal, so callers can fall back to reading a piped line instead.
var ErrNotATerminal = errors.New("standard input is not a terminal")

// ReadLine consumes a single line, one byte at a time. A buffered reader would
// swallow whatever follows the newline, which matters here because callers read
// a second line to confirm a passphrase.
func ReadLine(f io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				line = append(line, buf[0])
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	return string(line), nil
}
