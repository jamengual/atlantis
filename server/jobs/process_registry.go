// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DefaultStopGracePeriod is how long a stopped job's processes have to exit
// after the interrupt before Atlantis kills them. Terraform finishes the
// operations in flight before it exits, and creating some cloud resources
// takes several minutes, so the default is generous.
const DefaultStopGracePeriod = 10 * time.Minute

// stoppedRetention is how long a stop is remembered after it was requested,
// so pages can still say who stopped a finished job.
const stoppedRetention = 24 * time.Hour

// StopInfo records who stopped a job.
type StopInfo struct {
	By string
	At time.Time
	// Killed is true when a process ignored the interrupt for the grace
	// period and was killed. Terraform may then still hold its state lock.
	Killed bool
}

// StopError is returned by a command that was interrupted, or not started,
// because its job was stopped.
type StopError struct {
	Info StopInfo
	// Err is the command's own error, if it ran.
	Err error
}

func (e *StopError) Error() string {
	msg := "stopped by " + e.Info.By + " from the Atlantis web UI"
	if e.Info.Killed {
		msg += "; the process ignored the interrupt and was killed, so Terraform may still hold the state lock"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *StopError) Unwrap() error { return e.Err }

// ProcessRegistry tracks the processes each job runs, so that a running job
// can be stopped. Stopping a job sends its processes an interrupt, as
// pressing Ctrl-C in a terminal would, which lets Terraform finish in-flight
// operations, save state, and release its state lock. A process still
// running after the grace period is killed. Once a job is stopped, later
// steps of the job don't start.
//
// The registry lives in memory, so only the replica running a job can stop
// it. A nil *ProcessRegistry tracks nothing and never reports a job stopped.
type ProcessRegistry struct {
	// GracePeriod overrides DefaultStopGracePeriod.
	GracePeriod time.Duration
	// Now returns the current time. Tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	running map[string]map[*trackedProcess]struct{}
	stopped map[string]*StopInfo
}

type trackedProcess struct {
	jobID  string
	cmd    *exec.Cmd
	notify func(string)
	timer  *time.Timer
}

// NewProcessRegistry returns an empty registry.
func NewProcessRegistry() *ProcessRegistry {
	return &ProcessRegistry{
		running: map[string]map[*trackedProcess]struct{}{},
		stopped: map[string]*StopInfo{},
	}
}

func (r *ProcessRegistry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ProcessRegistry) grace() time.Duration {
	if r.GracePeriod > 0 {
		return r.GracePeriod
	}
	return DefaultStopGracePeriod
}

// Prepare readies cmd, before it starts, to be stopped with every process it
// starts. On Unix it runs in its own process group.
func (r *ProcessRegistry) Prepare(cmd *exec.Cmd) {
	if r == nil {
		return
	}
	ownProcessGroup(cmd)
}

// Track records a started command for jobID and returns a function to call
// once the command has exited. notify, which may be nil, writes a line to
// the job's output. If the job was already stopped, the command is
// interrupted at once.
func (r *ProcessRegistry) Track(jobID string, cmd *exec.Cmd, notify func(string)) (done func()) {
	if r == nil || jobID == "" || cmd == nil || cmd.Process == nil {
		return func() {}
	}
	p := &trackedProcess{jobID: jobID, cmd: cmd, notify: notify}
	r.mu.Lock()
	if r.running[jobID] == nil {
		r.running[jobID] = map[*trackedProcess]struct{}{}
	}
	r.running[jobID][p] = struct{}{}
	_, stopped := r.stopped[jobID]
	if stopped {
		r.interruptLocked(p)
	}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if p.timer != nil {
			p.timer.Stop()
		}
		delete(r.running[jobID], p)
		if len(r.running[jobID]) == 0 {
			delete(r.running, jobID)
		}
	}
}

// Stop marks a job stopped and interrupts its running processes. It returns
// the stop's details and whether this call stopped the job; when the job was
// already stopped, it returns the earlier stop. Stopping a job that has no
// process running right now still keeps its next step from starting.
func (r *ProcessRegistry) Stop(jobID, by string) (StopInfo, bool) {
	if r == nil {
		return StopInfo{}, false
	}
	r.mu.Lock()
	r.pruneLocked()
	if info, ok := r.stopped[jobID]; ok {
		earlier := *info
		r.mu.Unlock()
		return earlier, false
	}
	// The name appears in pull request comments, inside code blocks.
	by = strings.TrimSpace(strings.NewReplacer("`", "", "\n", " ", "\r", " ").Replace(by))
	info := &StopInfo{By: by, At: r.now()}
	r.stopped[jobID] = info
	var notify []func(string)
	for p := range r.running[jobID] {
		r.interruptLocked(p)
		if p.notify != nil {
			notify = append(notify, p.notify)
		}
	}
	result := *info
	r.mu.Unlock()
	msg := fmt.Sprintf("[atlantis] Stopped by %s. Sent an interrupt; Terraform stops after the operations in progress finish and releases its state lock.", by)
	for _, n := range notify {
		n(msg)
	}
	return result, true
}

func (r *ProcessRegistry) interruptLocked(p *trackedProcess) {
	if p.timer != nil {
		return
	}
	interruptProcess(p.cmd)
	p.timer = time.AfterFunc(r.grace(), func() { r.kill(p) })
}

func (r *ProcessRegistry) kill(p *trackedProcess) {
	r.mu.Lock()
	if _, ok := r.running[p.jobID][p]; !ok {
		r.mu.Unlock()
		return
	}
	if info, ok := r.stopped[p.jobID]; ok {
		info.Killed = true
	}
	r.mu.Unlock()
	// Say why before the process goes, so the line lands in the job output
	// ahead of the job's end.
	if p.notify != nil {
		p.notify(fmt.Sprintf("[atlantis] The process didn't exit within %s of the interrupt, so Atlantis killed it. Terraform may still hold the state lock; check it and run terraform force-unlock if needed.", r.grace()))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.running[p.jobID][p]; ok {
		killProcess(p.cmd)
	}
}

// pruneLocked forgets old stops of jobs with no process left.
func (r *ProcessRegistry) pruneLocked() {
	cutoff := r.now().Add(-stoppedRetention)
	for id, info := range r.stopped {
		if info.At.Before(cutoff) && len(r.running[id]) == 0 {
			delete(r.stopped, id)
		}
	}
}

// Stopped returns who stopped a job, if anyone did.
func (r *ProcessRegistry) Stopped(jobID string) (StopInfo, bool) {
	if r == nil || jobID == "" {
		return StopInfo{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.stopped[jobID]
	if !ok {
		return StopInfo{}, false
	}
	return *info, true
}

// Running returns how many processes the job has running.
func (r *ProcessRegistry) Running(jobID string) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running[jobID])
}

// Err returns a *StopError when the job was stopped, and nil otherwise. Steps
// call it before they start.
func (r *ProcessRegistry) Err(jobID string) error {
	return r.Wrap(jobID, nil)
}

// Wrap returns err as a *StopError when the job was stopped, so the error
// says who stopped it. Otherwise it returns err unchanged.
func (r *ProcessRegistry) Wrap(jobID string, err error) error {
	info, ok := r.Stopped(jobID)
	if !ok {
		return err
	}
	return &StopError{Info: info, Err: err}
}

// CombinedOutput runs cmd like exec.Cmd.CombinedOutput, tracked under jobID.
// It doesn't start cmd when the job was already stopped.
func (r *ProcessRegistry) CombinedOutput(jobID string, cmd *exec.Cmd, notify func(string)) ([]byte, error) {
	if err := r.Err(jobID); err != nil {
		return nil, err
	}
	r.Prepare(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := r.Track(jobID, cmd, notify)
	err := cmd.Wait()
	done()
	if err != nil {
		err = r.Wrap(jobID, err)
	}
	return out.Bytes(), err
}
