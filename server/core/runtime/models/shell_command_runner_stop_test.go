// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package models_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/runtime/models"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

// A command that stands in for a long Terraform run: it handles the
// interrupt the way Terraform does, by printing a message and exiting.
const fakeTerraform = `trap 'echo "Interrupt received. Gracefully shutting down..."; exit 1' INT
echo "Refreshing state..."
while :; do sleep 0.05; done`

func TestShellCommandRunner_StopInterruptsTheCommand(t *testing.T) {
	r := jobs.NewProcessRegistry()
	ctx := command.ProjectContext{Log: logging.NewNoopLogger(t), JobID: "job-1", Workspace: "default", RepoRelDir: "."}
	runner := models.NewShellCommandRunner(nil, fakeTerraform, os.Environ(), t.TempDir(), true, &jobs.NoopProjectOutputHandler{}).WithProcesses(r)

	_, outCh := runner.RunCommandAsync(ctx)
	first := <-outCh
	Equals(t, "Refreshing state...", first.Line)
	_, ok := r.Stop("job-1", "Ada Admin")
	Assert(t, ok, "stop")

	var lines []string
	var err error
	timeout := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case l, open := <-outCh:
			if !open {
				done = true
				break
			}
			if l.Err != nil {
				err = l.Err
				continue
			}
			lines = append(lines, l.Line)
		case <-timeout:
			t.Fatal("command still running after the stop")
		}
	}
	Assert(t, strings.Contains(strings.Join(lines, "\n"), "Interrupt received"), "command did not get the interrupt: %q", lines)
	var stopErr *jobs.StopError
	Assert(t, errors.As(err, &stopErr), "expected a StopError, got %v", err)
	ErrContains(t, "stopped by Ada Admin from the Atlantis web UI: running", err)
	Equals(t, 0, r.Running("job-1"))
}

func TestShellCommandRunner_StoppedJobDoesNotStartTheCommand(t *testing.T) {
	r := jobs.NewProcessRegistry()
	r.Stop("job-1", "alice")
	dir := t.TempDir()
	ctx := command.ProjectContext{Log: logging.NewNoopLogger(t), JobID: "job-1"}
	runner := models.NewShellCommandRunner(nil, "touch ran", os.Environ(), dir, true, &jobs.NoopProjectOutputHandler{}).WithProcesses(r)
	_, err := runner.Run(ctx)
	ErrEquals(t, "stopped by alice from the Atlantis web UI", err)
	_, statErr := os.Stat(filepath.Join(dir, "ran"))
	Assert(t, os.IsNotExist(statErr), "the command ran after its job was stopped")

	// Other jobs are unaffected.
	ctx.JobID = "job-2"
	runner = models.NewShellCommandRunner(nil, "touch ran", os.Environ(), dir, true, &jobs.NoopProjectOutputHandler{}).WithProcesses(r)
	_, err = runner.Run(ctx)
	Ok(t, err)
}
