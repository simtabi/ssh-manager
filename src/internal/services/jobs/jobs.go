// Package jobs runs a change that takes longer than a request, or reaches
// another machine, as a job: one at a time, under the advisory lock for as
// long as it runs, with its output kept line by line for a page to stream.
//
// A job is a person's confirmed command, run exactly as the CLI runs it. It
// can pause to ask the person something (rotate's "pasted the key?"), and it
// can be cancelled, which stops it between steps - never inside one, so a
// cancelled job never leaves a step half done. It holds the process's one
// change slot (mutation.Exclusive) from start to end, so no preview, change
// or other job interleaves with it.
package jobs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/history"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// States a job is in.
const (
	Running   = "running"
	Waiting   = "waiting" // paused on a question
	Done      = "done"
	Failed    = "failed"
	Cancelled = "cancelled"
)

// ErrCancelled is what a job's steps return once it has been cancelled. The
// history records the job as aborted.
var ErrCancelled = fmt.Errorf("cancelled: the steps before this one finished, and nothing after it ran: %w",
	mutation.ErrDeclined)

// Question is what a paused job is asking. Text is shown as is, for copying:
// rotate's staged public key.
type Question struct {
	Prompt string
	Text   string
}

// View is a job as a page shows it.
type View struct {
	ID, Command, State, Err, OpID string
	Args                          []string
	Lines                         []string
	Question                      *Question
	Started                       time.Time
}

// Job is one running or finished job.
type Job struct {
	id      string
	command string
	args    []string
	started time.Time

	mu       sync.Mutex
	lines    []string
	partial  string
	state    string
	err      string
	opID     string
	question *Question
	changed  chan struct{} // closed and replaced on every update
	answer   chan bool
	cancel   bool
}

// Write appends output, one line at a time, so a page can stream it.
func (j *Job) Write(b []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	text := j.partial + string(b)
	parts := strings.Split(text, "\n")
	j.partial = parts[len(parts)-1]
	j.lines = append(j.lines, parts[:len(parts)-1]...)
	j.notify()
	return len(b), nil
}

// Ask pauses the job until the person answers, and reports their answer. A
// cancel answers no.
func (j *Job) Ask(prompt, text string) bool {
	j.mu.Lock()
	if j.cancel {
		j.mu.Unlock()
		return false
	}
	j.question = &Question{Prompt: prompt, Text: text}
	j.state = Waiting
	j.notify()
	j.mu.Unlock()
	yes := <-j.answer
	j.mu.Lock()
	j.question, j.state = nil, Running
	j.notify()
	j.mu.Unlock()
	return yes
}

// Step reports ErrCancelled once the job has been cancelled; a job calls it
// between its steps.
func (j *Job) Step() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel {
		return ErrCancelled
	}
	return nil
}

// View is the job as it is now, and a channel closed at its next change.
func (j *Job) View() (View, <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := append([]string(nil), j.lines...)
	if j.partial != "" && j.finished() {
		lines = append(lines, j.partial)
	}
	v := View{ID: j.id, Command: j.command, Args: j.args, State: j.state, Err: j.err, OpID: j.opID,
		Lines: lines, Started: j.started}
	if j.question != nil {
		q := *j.question
		v.Question = &q
	}
	return v, j.changed
}

func (j *Job) finished() bool { return j.state == Done || j.state == Failed || j.state == Cancelled }

// notify wakes everyone waiting on the job. Called with mu held.
func (j *Job) notify() {
	close(j.changed)
	j.changed = make(chan struct{})
}

// Registry holds the jobs a server has started, and allows one to run at a
// time.
type Registry struct {
	mu      sync.Mutex
	jobs    map[string]*Job
	order   []string
	running *Job
}

// NewRegistry is an empty registry.
func NewRegistry() *Registry { return &Registry{jobs: map[string]*Job{}} }

// keep is how many finished jobs a registry remembers.
const keep = 50

// ErrBusy names the job already running.
type ErrBusy struct{ ID, Command string }

func (e ErrBusy) Error() string {
	return "sshmgr " + e.Command + " is still running; one change runs at a time"
}

// Start runs run as a job on p, under the lock, as one operation in the
// history. It refuses while another job runs, and waits briefly for a preview
// or change in flight. The job runs on after Start returns.
func (r *Registry) Start(p paths.Paths, scope mutation.Scope, run func(j *Job) error) (*Job, error) {
	r.mu.Lock()
	if r.running != nil {
		busy := ErrBusy{ID: r.running.id, Command: r.running.command}
		r.mu.Unlock()
		return nil, busy
	}
	r.mu.Unlock()
	release, err := mutation.Exclusive(10 * time.Second)
	if err != nil {
		return nil, err
	}
	if scope.OpID == "" {
		scope.OpID = history.NewOpID()
	}
	j := &Job{id: newID(), command: scope.Command, args: scope.Args, started: time.Now(),
		state: Running, opID: scope.OpID, changed: make(chan struct{}), answer: make(chan bool, 1)}
	r.mu.Lock()
	r.running = j
	r.jobs[j.id] = j
	r.order = append(r.order, j.id)
	for len(r.order) > keep {
		delete(r.jobs, r.order[0])
		r.order = r.order[1:]
	}
	r.mu.Unlock()
	go func() {
		defer release()
		err := mutation.Scoped(p, scope, func() error { return run(j) })
		j.mu.Lock()
		switch {
		case errors.Is(err, ErrCancelled):
			j.state, j.err = Cancelled, err.Error()
		case err != nil:
			j.state, j.err = Failed, err.Error()
		default:
			j.state = Done
		}
		j.notify()
		j.mu.Unlock()
		r.mu.Lock()
		r.running = nil
		r.mu.Unlock()
	}()
	return j, nil
}

// Get is the job with id, or nil.
func (r *Registry) Get(id string) *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobs[id]
}

// Running is the job running now, or nil.
func (r *Registry) Running() *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Answer answers the question a job is waiting on. It reports false when the
// job is not waiting.
func (r *Registry) Answer(id string, yes bool) bool {
	j := r.Get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	waiting := j.state == Waiting
	j.mu.Unlock()
	if !waiting {
		return false
	}
	select {
	case j.answer <- yes:
		return true
	default:
		return false // answered already
	}
}

// Cancel stops a job at its next step, answering no to a question it waits on.
func (r *Registry) Cancel(id string) bool {
	j := r.Get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	if j.finished() {
		j.mu.Unlock()
		return false
	}
	j.cancel = true
	waiting := j.state == Waiting
	j.notify()
	j.mu.Unlock()
	if waiting {
		select {
		case j.answer <- false:
		default:
		}
	}
	return true
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
