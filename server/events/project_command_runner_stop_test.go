// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package events_test

import (
	"errors"
	"testing"

	. "github.com/petergtz/pegomock/v4"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/mocks"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

type stopFixture struct {
	runner     events.DefaultProjectCommandRunner
	init, plan *mocks.MockStepRunner
	show       *mocks.MockStepRunner
	workingDir *mocks.MockWorkingDir
	processes  *jobs.ProcessRegistry
	unlocked   int
	ctx        command.ProjectContext
	repoDir    string
}

func newStopFixture(t *testing.T) *stopFixture {
	RegisterMockTestingT(t)
	f := &stopFixture{
		init:       mocks.NewMockStepRunner(),
		plan:       mocks.NewMockStepRunner(),
		show:       mocks.NewMockStepRunner(),
		workingDir: mocks.NewMockWorkingDir(),
		processes:  jobs.NewProcessRegistry(),
		repoDir:    t.TempDir(),
	}
	locker := mocks.NewMockProjectLocker()
	requirements := mocks.NewMockCommandRequirementHandler()
	f.runner = events.DefaultProjectCommandRunner{
		Locker:                    locker,
		LockURLGenerator:          mockURLGenerator{},
		InitStepRunner:            f.init,
		PlanStepRunner:            f.plan,
		ShowStepRunner:            f.show,
		WorkingDir:                f.workingDir,
		WorkingDirLocker:          events.NewDefaultWorkingDirLocker(),
		CommandRequirementHandler: requirements,
		Processes:                 f.processes,
	}
	When(f.workingDir.Clone(Any[logging.SimpleLogging](), Any[models.Repo](), Any[models.PullRequest](), Any[string]())).ThenReturn(f.repoDir, nil)
	When(f.workingDir.GitReadLock(Any[models.Repo](), Any[models.PullRequest](), Any[string]())).ThenReturn(func() {})
	When(locker.TryLock(Any[logging.SimpleLogging](), Any[models.PullRequest](), Any[models.User](), Any[string](), Any[models.Project](), AnyBool())).
		ThenReturn(&events.TryLockResponse{LockAcquired: true, LockKey: "lock-key", UnlockFn: func() error { f.unlocked++; return nil }}, nil)
	f.ctx = command.ProjectContext{
		Log:        logging.NewNoopLogger(t),
		JobID:      "job-1",
		Steps:      []valid.Step{{StepName: "init"}, {StepName: "plan"}, {StepName: "show"}},
		Workspace:  "default",
		RepoRelDir: ".",
	}
	return f
}

// Terraform can finish the plan just as the interrupt arrives. The plan
// still fails, the steps after it don't run, and its plan file is deleted so
// it can't be applied.
func TestDefaultProjectCommandRunner_StoppedPlanLeavesNothingToApply(t *testing.T) {
	f := newStopFixture(t)
	When(f.init.Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())).ThenReturn("init", nil)
	When(f.plan.Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())).Then(func([]Param) ReturnValues {
		f.processes.Stop("job-1", "Ada Admin")
		return ReturnValues{"Plan: 1 to add, 0 to change, 0 to destroy.", nil}
	})

	res := f.runner.Plan(f.ctx)

	Assert(t, res.PlanSuccess == nil, "a stopped plan must not succeed")
	ErrContains(t, "stopped by Ada Admin from the Atlantis web UI", res.Error)
	var stopErr *jobs.StopError
	Assert(t, errors.As(res.Error, &stopErr), "the error should be a StopError: %v", res.Error)
	f.show.VerifyWasCalled(Never()).Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())
	f.workingDir.VerifyWasCalledOnce().DeletePlan(Any[logging.SimpleLogging](), Any[models.Repo](), Any[models.PullRequest](), Eq("default"), Eq("."), Eq(""))
	Equals(t, 1, f.unlocked)
}

// A job stopped before its steps start runs none of them.
func TestDefaultProjectCommandRunner_StoppedJobRunsNoSteps(t *testing.T) {
	f := newStopFixture(t)
	f.processes.Stop("job-1", "alice")

	res := f.runner.Plan(f.ctx)

	ErrContains(t, "stopped by alice", res.Error)
	f.init.VerifyWasCalled(Never()).Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())
	f.plan.VerifyWasCalled(Never()).Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())
}

// Other jobs, and runners without a registry, are unaffected.
func TestDefaultProjectCommandRunner_UnstoppedPlanRunsNormally(t *testing.T) {
	f := newStopFixture(t)
	f.processes.Stop("another-job", "alice")
	f.ctx.Steps = []valid.Step{{StepName: "init"}}
	When(f.init.Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())).ThenReturn("init", nil)

	res := f.runner.Plan(f.ctx)
	Ok(t, res.Error)
	Assert(t, res.PlanSuccess != nil, "plan should succeed")

	f.runner.Processes = nil
	res = f.runner.Plan(f.ctx)
	Ok(t, res.Error)
}
