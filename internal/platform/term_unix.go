//go:build linux || darwin

package platform

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// StdinIsTerminal reports whether standard input is a terminal.
func StdinIsTerminal() bool {
	var t syscall.Termios
	return ioctlTermios(os.Stdin.Fd(), ioctlReadTermios, &t) == nil
}

func ioctlTermios(fd, req uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, req,
		uintptr(unsafe.Pointer(t)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// ReadSecret prompts on stderr and reads one line with terminal echo disabled.
// The previous terminal state is restored before returning, including when the
// user interrupts the prompt, so a cancelled read cannot leave the terminal
// unable to echo.
func ReadSecret(prompt string) (string, error) {
	fd := os.Stdin.Fd()
	var before syscall.Termios
	if err := ioctlTermios(fd, ioctlReadTermios, &before); err != nil {
		return "", ErrNotATerminal
	}
	quiet := before
	quiet.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, ioctlWriteTermios, &quiet); err != nil {
		return "", err
	}
	restore := func() { _ = ioctlTermios(fd, ioctlWriteTermios, &before) }
	defer restore()

	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupted:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()

	fmt.Fprint(os.Stderr, prompt)
	line, err := ReadLine(os.Stdin)
	fmt.Fprintln(os.Stderr) // the Enter keystroke was not echoed
	return line, err
}
