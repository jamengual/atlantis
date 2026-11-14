// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package jobs_test

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/jobs"
	. "github.com/runatlantis/atlantis/testing"
)

// notes collects the lines the registry writes to a job's output.
type notes struct {
	mu    sync.Mutex
	lines []string
}

func (n *notes) add(s string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lines = append(n.lines, s)
}

func (n *notes) all() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(n.lines, "\n")
}

// startScript starts a long-running shell script under the registry and
// waits until it prints "ready", so its signal handlers are installed.
func startScript(t *testing.T, r *jobs.ProcessRegistry, jobID, script string, n *notes) (*exec.Cmd, func() (string, error)) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	r.Prepare(cmd)
	stdout, err := cmd.StdoutPipe()
	Ok(t, err)
	Ok(t, cmd.Start())
	done := r.Track(jobID, cmd, n.add)
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	rd := bufio.NewReader(stdout)
	line, err := rd.ReadString('\n')
	Ok(t, err)
	Equals(t, "ready\n", line)
	return cmd, func() (string, error) {
		rest, _ := io.ReadAll(rd)
		err := cmd.Wait()
		done()
		return string(rest), err
	}
}

func waitWithin(t *testing.T, d time.Duration, wait func() (string, error)) (string, error) {
	t.Helper()
	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := wait()
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(d):
		t.Fatalf("process still running after %s", d)
		return "", nil
	}
}

func TestProcessRegistry_StopInterruptsTheWholeProcessGroup(t *testing.T) {
	r := jobs.NewProcessRegistry()
	n := &notes{}
	// The inner shell stands in for Terraform under a run step: only a
	// signal to the process group reaches it.
	script := `sh -c 'trap "echo child-interrupted; exit 0" INT; echo ready; while :; do sleep 0.05; done'`
	_, wait := startScript(t, r, "job-1", script, n)
	Equals(t, 1, r.Running("job-1"))

	info, first := r.Stop("job-1", "Ada Admin")
	Assert(t, first, "first stop should report that it stopped the job")
	Equals(t, "Ada Admin", info.By)

	out, _ := waitWithin(t, 5*time.Second, wait)
	Assert(t, strings.Contains(out, "child-interrupted"), "child did not get the interrupt, output %q", out)
	Assert(t, strings.Contains(n.all(), "Stopped by Ada Admin"), "job output does not say who stopped it: %q", n.all())
	Equals(t, 0, r.Running("job-1"))
	got, ok := r.Stopped("job-1")
	Assert(t, ok && !got.Killed, "stop not recorded, or recorded as killed: %+v", got)
}

func TestProcessRegistry_KillsAfterTheGracePeriod(t *testing.T) {
	r := jobs.NewProcessRegistry()
	r.GracePeriod = 200 * time.Millisecond
	n := &notes{}
	_, wait := startScript(t, r, "job-1", `trap "echo ignoring" INT; echo ready; while :; do sleep 0.05; done`, n)

	r.Stop("job-1", "alice")
	_, err := waitWithin(t, 5*time.Second, wait)
	var exitErr *exec.ExitError
	Assert(t, errors.As(err, &exitErr), "expected the process to be killed, got %v", err)
	info, _ := r.Stopped("job-1")
	Assert(t, info.Killed, "stop should record that the process was killed")
	Assert(t, strings.Contains(n.all(), "force-unlock"), "job output should warn about the state lock: %q", n.all())
	ErrContains(t, "may still hold the state lock", r.Err("job-1"))
}

func TestProcessRegistry_ProcessExitingInTimeIsNotKilled(t *testing.T) {
	r := jobs.NewProcessRegistry()
	r.GracePeriod = 100 * time.Millisecond
	_, wait := startScript(t, r, "job-1", `trap "exit 1" INT; echo ready; while :; do sleep 0.05; done`, &notes{})
	r.Stop("job-1", "alice")
	_, err := waitWithin(t, 5*time.Second, wait)
	Assert(t, err != nil, "interrupted script should fail")
	time.Sleep(300 * time.Millisecond)
	info, _ := r.Stopped("job-1")
	Assert(t, !info.Killed, "a process that exited after the interrupt was marked killed")
}

func TestProcessRegistry_StoppedJobStartsNothingNew(t *testing.T) {
	r := jobs.NewProcessRegistry()
	r.Stop("job-1", "alice")

	marker := filepath.Join(t.TempDir(), "ran")
	out, err := r.CombinedOutput("job-1", exec.Command("touch", marker), nil)
	Equals(t, 0, len(out))
	var stopErr *jobs.StopError
	Assert(t, errors.As(err, &stopErr), "expected a StopError, got %v", err)
	Equals(t, "alice", stopErr.Info.By)
	_, statErr := os.Stat(marker)
	Assert(t, os.IsNotExist(statErr), "the command ran after the job was stopped")

	// A process started anyway, for example in a race with the stop, is
	// interrupted as soon as it is tracked.
	n := &notes{}
	cmd := exec.Command("sh", "-c", `while :; do sleep 0.05; done`)
	r.Prepare(cmd)
	Ok(t, cmd.Start())
	done := r.Track("job-1", cmd, n.add)
	_, err = waitWithin(t, 5*time.Second, func() (string, error) { e := cmd.Wait(); done(); return "", e })
	// Depending on timing the shell exits from its trap or from the signal.
	Assert(t, err != nil, "late process was not interrupted")
}

func TestProcessRegistry_StopIsIdempotentAndSanitizesTheName(t *testing.T) {
	r := jobs.NewProcessRegistry()
	first, ok := r.Stop("job-1", "Eve `rm -rf`\nInjected")
	Assert(t, ok, "first stop")
	Equals(t, "Eve rm -rf Injected", first.By)
	again, ok := r.Stop("job-1", "bob")
	Assert(t, !ok, "second stop should report the earlier one")
	Equals(t, first.By, again.By)

	Equals(t, "stopped by Eve rm -rf Injected from the Atlantis web UI", r.Err("job-1").Error())
	wrapped := r.Wrap("job-1", errors.New("exit status 1"))
	ErrEquals(t, "stopped by Eve rm -rf Injected from the Atlantis web UI: exit status 1", wrapped)
	Assert(t, errors.Unwrap(wrapped).Error() == "exit status 1", "StopError should unwrap to the command's error")
	Ok(t, r.Err("job-2"))
	ErrEquals(t, "boom", r.Wrap("job-2", errors.New("boom")))
}

func TestProcessRegistry_ForgetsOldStops(t *testing.T) {
	clock := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	r := jobs.NewProcessRegistry()
	r.Now = func() time.Time { return clock }
	r.Stop("old", "alice")
	clock = clock.Add(25 * time.Hour)
	r.Stop("new", "bob")
	_, ok := r.Stopped("old")
	Assert(t, !ok, "a day-old stop should be forgotten")
	_, ok = r.Stopped("new")
	Assert(t, ok, "the new stop should be kept")
}

func TestProcessRegistry_NilIsSafe(t *testing.T) {
	var r *jobs.ProcessRegistry
	cmd := exec.Command("sh", "-c", "echo hi")
	r.Prepare(cmd)
	Assert(t, cmd.SysProcAttr == nil, "a nil registry must leave commands unchanged")
	out, err := r.CombinedOutput("job-1", cmd, nil)
	Ok(t, err)
	Equals(t, "hi\n", string(out))
	_, ok := r.Stop("job-1", "alice")
	Assert(t, !ok, "nil registry can't stop jobs")
	Ok(t, r.Err("job-1"))
	Equals(t, 0, r.Running("job-1"))
	r.Track("job-1", cmd, nil)()
}
