package jobs

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

func home(t *testing.T) paths.Paths {
	t.Helper()
	t.Setenv("SSH_MANAGER_HISTORY", "0")
	base := t.TempDir()
	t.Cleanup(mutation.Release)
	return paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
}

// until waits for the job to reach state, or fails.
func until(t *testing.T, j *Job, state string) View {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		v, changed := j.View()
		if v.State == state {
			return v
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("job is %s, want %s; output %q", v.State, state, v.Lines)
		}
	}
}

// A job's output is kept line by line, it holds the lock while it runs, and
// it gives the lock back when it ends.
func TestAJobRunsUnderTheLockAndKeepsItsOutput(t *testing.T) {
	p := home(t)
	r := NewRegistry()
	held := make(chan bool, 1)
	j, err := r.Start(p, mutation.Scope{Command: "deploy", Args: []string{"work/gh"}}, func(j *Job) error {
		held <- mutation.Held()
		_, _ = fmt.Fprintln(j, "one")
		_, _ = fmt.Fprint(j, "two")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	v := until(t, j, Done)
	if !<-held {
		t.Error("the job ran without the lock")
	}
	if strings.Join(v.Lines, "|") != "one|two" {
		t.Errorf("lines = %q", v.Lines)
	}
	if mutation.Held() {
		t.Error("the lock was not given back")
	}
	if r.Running() != nil {
		t.Error("a finished job still counts as running")
	}
}

// One job at a time: a second is refused with the first's name, and no
// preview or change runs alongside either.
func TestOneJobAtATime(t *testing.T) {
	p := home(t)
	r := NewRegistry()
	j, err := r.Start(p, mutation.Scope{Command: "rotate"}, func(j *Job) error {
		if !j.Ask("Pasted it?", "ssh-ed25519 AAAA new") {
			return ErrCancelled
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	v := until(t, j, Waiting)
	if v.Question == nil || v.Question.Text != "ssh-ed25519 AAAA new" {
		t.Errorf("question = %+v", v.Question)
	}
	_, err = r.Start(p, mutation.Scope{Command: "deploy"}, func(*Job) error { return nil })
	var busy ErrBusy
	if !errors.As(err, &busy) || busy.ID != j.id {
		t.Errorf("a second job: %v", err)
	}
	if release, err := mutation.Exclusive(50 * time.Millisecond); err == nil {
		release()
		t.Error("a change could run while a job did")
	}
	if !r.Answer(j.id, true) {
		t.Fatal("the answer was not taken")
	}
	until(t, j, Done)
}

// Cancelling stops a job at its next step, answers no to a question it is
// waiting on, and records it as cancelled.
func TestCancelStopsBetweenSteps(t *testing.T) {
	p := home(t)
	r := NewRegistry()
	reached := make(chan struct{})
	proceed := make(chan struct{})
	ran := 0
	j, err := r.Start(p, mutation.Scope{Command: "deploy"}, func(j *Job) error {
		for i := 0; i < 3; i++ {
			if err := j.Step(); err != nil {
				return err
			}
			ran++
			if i == 0 {
				close(reached)
				<-proceed
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if !r.Cancel(j.id) {
		t.Fatal("cancel refused")
	}
	close(proceed)
	v := until(t, j, Cancelled)
	if ran != 1 {
		t.Errorf("%d steps ran after a cancel during the first", ran)
	}
	if !strings.Contains(v.Err, "cancelled") {
		t.Errorf("err = %q", v.Err)
	}

	// A cancel while waiting answers the question no.
	j, _ = r.Start(p, mutation.Scope{Command: "rotate"}, func(j *Job) error {
		if !j.Ask("Pasted it?", "") {
			return ErrCancelled
		}
		return nil
	})
	until(t, j, Waiting)
	r.Cancel(j.id)
	until(t, j, Cancelled)
}
