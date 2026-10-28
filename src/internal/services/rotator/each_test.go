package rotator

import (
	"errors"
	"io"
	"testing"
)

// next runs before every key, and an error from it stops the batch before
// that key is touched: a web job's cancel.
func TestRotateEachStopsWhenNextSaysSo(t *testing.T) {
	stop := errors.New("cancelled")
	calls := 0
	failed, err := (&Rotator{}).RotateEach([]string{"work/a", "work/b"}, false, "", io.Discard, nil,
		func() error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 || len(failed) != 0 {
		t.Errorf("err %v after %d call(s), failed %v", err, calls, failed)
	}
}
