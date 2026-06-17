//go:build !darwin && !linux && !windows

package scheduler

import "fmt"

// Install is unsupported on this OS.
func Install(command, label string) error {
	return fmt.Errorf("no scheduler backend for this OS")
}
