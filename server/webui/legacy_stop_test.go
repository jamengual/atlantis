// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package webui_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/runtime/models"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// The UI's stop action reaches a real process through the same runner,
// registry, and output handler that Terraform commands use.
func TestLegacyActions_StopJobInterruptsTheRunningCommand(t *testing.T) {
	f := newFixture(t)
	processes := jobs.NewProcessRegistry()
	f.store.Stops = processes
	actions := &webui.LegacyActions{Stopper: processes}

	ctx := command.ProjectContext{
		Log: logging.NewNoopLogger(t), JobID: "job-live", Pull: pull(5), BaseRepo: testRepo,
		RepoRelDir: "network", Workspace: "default", CommandName: command.Plan,
	}
	script := `trap 'echo "Interrupt received. Gracefully shutting down..."; exit 1' INT; echo "Refreshing state..."; while :; do sleep 0.05; done`
	runner := models.NewShellCommandRunner(nil, script, os.Environ(), t.TempDir(), true, f.handler).WithProcesses(processes)
	errCh := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx)
		f.handler.Send(ctx, "", true)
		errCh <- err
	}()
	waitFor(t, func() bool { return processes.Running("job-live") == 1 })
	waitFor(t, func() bool { j, ok := f.store.GetJob(context.Background(), "job-live"); return ok && j.Lines >= 1 })

	j, _ := f.store.GetJob(context.Background(), "job-live")
	Equals(t, webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, j.Repo)
	Assert(t, j.Stoppable(), "running job should be stoppable")

	stop, first, err := actions.StopJob("job-live", "Ada Admin")
	Ok(t, err)
	Assert(t, first, "first stop")
	Equals(t, "Ada Admin", stop.By)

	select {
	case err := <-errCh:
		ErrContains(t, "stopped by Ada Admin", err)
	case <-time.After(5 * time.Second):
		t.Fatal("command still running after the stop")
	}
	waitFor(t, func() bool { j, _ := f.store.GetJob(context.Background(), "job-live"); return j.Done })
	j, _ = f.store.GetJob(context.Background(), "job-live")
	Assert(t, j.Stop != nil && j.Stop.By == "Ada Admin", "job should record who stopped it: %+v", j.Stop)
	Assert(t, !j.Stoppable(), "a stopped job can't be stopped again")

	var log []string
	for l := range f.store.JobLog(context.Background(), "job-live", 0) {
		log = append(log, l.Text)
	}
	all := strings.Join(log, "\n")
	Assert(t, strings.Contains(all, "[atlantis] Stopped by Ada Admin"), "log should say who stopped the job: %q", all)
	Assert(t, strings.Contains(all, "Interrupt received"), "the command should have seen the interrupt: %q", all)

	_, first, err = actions.StopJob("job-live", "bob")
	Ok(t, err)
	Assert(t, !first, "second stop should report the first")
}

func TestLegacyActions_StopJobWithoutRegistry(t *testing.T) {
	_, _, err := (&webui.LegacyActions{}).StopJob("job", "alice")
	ErrEquals(t, webui.ErrStopUnavailable.Error(), err)
}
