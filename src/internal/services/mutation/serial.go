package mutation

import (
	"errors"
	"time"
)

// ErrBusy reports that another change is being made by this process: in a
// server, a preview, a confirmed change or a job.
var ErrBusy = errors.New("another change is being made from this sshmgr serve; wait for it to finish, then try again")

// serial allows one change at a time in a process. The advisory lock
// serializes processes; within a server, two requests would otherwise share
// one lock and interleave, a preview's suspension of the history would
// swallow a job's events, and one Release would drop the other's lock.
var serial = make(chan struct{}, 1)

// Exclusive waits up to wait for the process's one change slot, and returns
// the function that gives it back. A job can hold the slot for as long as it
// waits on a person, so callers wait a short while and then say why.
func Exclusive(wait time.Duration) (release func(), err error) {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case serial <- struct{}{}:
		return func() { <-serial }, nil
	case <-t.C:
		return nil, ErrBusy
	}
}
