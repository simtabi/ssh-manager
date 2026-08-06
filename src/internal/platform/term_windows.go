//go:build windows

package platform

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableEchoInput = 0x0004

func consoleMode(fd uintptr) (uint32, error) {
	var mode uint32
	r, _, err := procGetConsoleMode.Call(fd, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return 0, err
	}
	return mode, nil
}

func setConsoleMode(fd uintptr, mode uint32) error {
	if r, _, err := procSetConsoleMode.Call(fd, uintptr(mode)); r == 0 {
		return err
	}
	return nil
}

// StdinIsTerminal reports whether standard input is a console.
func StdinIsTerminal() bool {
	_, err := consoleMode(os.Stdin.Fd())
	return err == nil
}

// ReadSecret prompts on stderr and reads one line with console echo disabled,
// restoring the previous console mode before returning.
func ReadSecret(prompt string) (string, error) {
	fd := os.Stdin.Fd()
	before, err := consoleMode(fd)
	if err != nil {
		return "", ErrNotATerminal
	}
	if err := setConsoleMode(fd, before&^enableEchoInput); err != nil {
		return "", err
	}
	defer func() { _ = setConsoleMode(fd, before) }()

	fmt.Fprint(os.Stderr, prompt)
	line, readErr := ReadLine(os.Stdin)
	fmt.Fprintln(os.Stderr) // the Enter keystroke was not echoed
	return line, readErr
}
