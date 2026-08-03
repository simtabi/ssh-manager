// Package platform isolates the OS-specific behaviour sshmgr needs, so the rest
// of the tree can stay free of runtime.GOOS branches. Today that is terminal
// handling for reading secrets without echoing them.
package platform

import (
	"errors"
	"io"
	"os"
)

// ErrNotATerminal is returned by ReadSecret when standard input is not a
// terminal, so callers can fall back to reading a piped line instead.
var ErrNotATerminal = errors.New("standard input is not a terminal")

// ReadLine consumes a single line, one byte at a time. A buffered reader would
// swallow whatever follows the newline, which matters here because callers read
// a second line to confirm a passphrase.
func ReadLine(f *os.File) (string, error) {
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
