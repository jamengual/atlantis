// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package events_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	. "github.com/petergtz/pegomock/v4"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/core/locking"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/mocks"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/events/models/testdata"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

var maintenanceStart = time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)

func startMaintenance(t *testing.T, w locking.MaintenanceWindow) *locking.Maintenance {
	t.Helper()
	m := locking.NewMaintenance()
	m.Now = func() time.Time { return maintenanceStart }
	_, err := m.Start(w)
	Ok(t, err)
	return m
}

// openPull makes the GitHub getter return an open pull request on main.
func openPull() models.PullRequest {
	pull := &github.PullRequest{State: github.Ptr("open")}
	modelPull := models.PullRequest{BaseRepo: testdata.GithubRepo, State: models.OpenPullState, Num: testdata.Pull.Num, BaseBranch: "main"}
	When(githubGetter.GetPullRequest(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(testdata.Pull.Num))).ThenReturn(pull, nil)
	When(eventParsing.ParseGithubPull(Any[logging.SimpleLogging](), Eq(pull))).ThenReturn(modelPull, modelPull.BaseRepo, testdata.GithubRepo, nil)
	return modelPull
}

const frozenAppliesComment = "```\n" +
	"Error: atlantis apply is blocked by a maintenance window on runatlantis/atlantis.\n" +
	"Scope: the whole repository\n" +
	"Reason: upgrading the state bucket\n" +
	"Set by: Ada Admin at 2026-11-13 14:00 UTC\n" +
	"Ends: 2026-11-13 18:00 UTC\n" +
	"```"

func TestRunCommentCommand_MaintenanceRejectsApply(t *testing.T) {
	vcsClient := setup(t)
	ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{
		Host: "github.com", RepoName: "runatlantis/atlantis", Reason: "upgrading the state bucket", By: "Ada Admin", Until: maintenanceStart.Add(4 * time.Hour),
	})
	modelPull := openPull()

	ch.RunCommentCommand(testdata.GithubRepo, nil, nil, testdata.User, modelPull.Num, &events.CommentCommand{Name: command.Apply})

	vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num), Eq(frozenAppliesComment), Eq("apply"))
	projectCommandBuilder.VerifyWasCalled(Never()).BuildApplyCommands(Any[*command.Context](), Any[*events.CommentCommand]())
	preWorkflowHooksCommandRunner.(*mocks.MockPreWorkflowHooksCommandRunner).VerifyWasCalled(Never()).RunPreHooks(Any[*command.Context](), Any[*events.CommentCommand]())
}

func TestRunCommentCommand_MaintenanceRejectsImportAndStateRm(t *testing.T) {
	for _, name := range []command.Name{command.Import, command.State} {
		t.Run(name.String(), func(t *testing.T) {
			vcsClient := setup(t)
			ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Reason: "freeze", By: "Ada"})
			modelPull := openPull()

			ch.RunCommentCommand(testdata.GithubRepo, nil, nil, testdata.User, modelPull.Num, &events.CommentCommand{Name: name})

			_, _, _, body, _ := vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num), Any[string](), Any[string]()).GetCapturedArguments()
			want := map[command.Name]string{command.Import: "atlantis import is blocked", command.State: "atlantis state rm is blocked"}[name]
			Assert(t, strings.Contains(body, want), "comment %q should contain %q", body, want)
			projectCommandBuilder.VerifyWasCalled(Never()).BuildImportCommands(Any[*command.Context](), Any[*events.CommentCommand]())
			projectCommandBuilder.VerifyWasCalled(Never()).BuildStateRmCommands(Any[*command.Context](), Any[*events.CommentCommand]())
		})
	}
}

func TestRunCommentCommand_MaintenanceAllowsPlansUnlessFrozen(t *testing.T) {
	vcsClient := setup(t)
	ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Reason: "applies only", By: "Ada"})
	modelPull := openPull()

	ch.RunCommentCommand(testdata.GithubRepo, nil, nil, testdata.User, modelPull.Num, &events.CommentCommand{Name: command.Plan})

	vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num), Eq("Ran Plan for 0 projects:"), Eq("plan"))
}

func TestRunCommentCommand_MaintenanceFreezingPlansRejectsPlan(t *testing.T) {
	vcsClient := setup(t)
	ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Plans: true, Reason: "incident 4211", By: "Ada"})
	modelPull := openPull()

	ch.RunCommentCommand(testdata.GithubRepo, nil, nil, testdata.User, modelPull.Num, &events.CommentCommand{Name: command.Plan})

	_, _, _, body, cmd := vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num), Any[string](), Any[string]()).GetCapturedArguments()
	Equals(t, "plan", cmd)
	Assert(t, strings.Contains(body, "atlantis plan is blocked by a maintenance window") && strings.Contains(body, "Reason: incident 4211") &&
		strings.Contains(body, "Ends: when someone ends it in the Atlantis web UI"), "unexpected comment %q", body)
	projectCommandBuilder.VerifyWasCalled(Never()).BuildPlanCommands(Any[*command.Context](), Any[*events.CommentCommand]())
}

func TestRunCommentCommand_MaintenanceOnAnotherRepoOrExpired(t *testing.T) {
	vcsClient := setup(t)
	m := locking.NewMaintenance()
	clock := maintenanceStart
	m.Now = func() time.Time { return clock }
	_, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/other", Reason: "elsewhere", By: "Ada"})
	Ok(t, err)
	_, err = m.Start(locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Reason: "ended", By: "Ada", Until: maintenanceStart.Add(time.Minute)})
	Ok(t, err)
	clock = maintenanceStart.Add(time.Hour)
	ch.Maintenance = m
	applyCommandRunner.DisableApplyAll = true
	modelPull := openPull()

	ch.RunCommentCommand(testdata.GithubRepo, nil, nil, testdata.User, modelPull.Num, &events.CommentCommand{Name: command.Apply})

	// The apply reaches the apply runner, which rejects it for its own reason.
	vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num),
		Eq("**Error:** Running `atlantis apply` without flags is disabled. You must specify which project to apply via the `-d <dir>`, `-w <workspace>` or `-p <project name>` flags."), Eq("apply"))
}

func TestRunAutoplanCommand_MaintenanceFreezingPlans(t *testing.T) {
	vcsClient := setup(t)
	ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Plans: true, Reason: "incident", By: "Ada"})
	modelPull := models.PullRequest{BaseRepo: testdata.GithubRepo, State: models.OpenPullState, Num: testdata.Pull.Num, BaseBranch: "main"}

	ch.RunAutoplanCommand(testdata.GithubRepo, testdata.GithubRepo, modelPull, testdata.User)

	_, _, _, body, cmd := vcsClient.VerifyWasCalledOnce().CreateComment(Any[logging.SimpleLogging](), Eq(testdata.GithubRepo), Eq(modelPull.Num), Any[string](), Any[string]()).GetCapturedArguments()
	Equals(t, "plan", cmd)
	Assert(t, strings.HasPrefix(body, "```\nError: Autoplan is blocked by a maintenance window"), "unexpected comment %q", body)
	projectCommandBuilder.VerifyWasCalled(Never()).BuildAutoplanCommands(Any[*command.Context]())
}

func TestRunAutoplanCommand_MaintenanceForAppliesLetsAutoplanRun(t *testing.T) {
	setup(t)
	ch.Maintenance = startMaintenance(t, locking.MaintenanceWindow{RepoName: "runatlantis/atlantis", Reason: "applies only", By: "Ada"})
	modelPull := models.PullRequest{BaseRepo: testdata.GithubRepo, State: models.OpenPullState, Num: testdata.Pull.Num, BaseBranch: "main"}

	ch.RunAutoplanCommand(testdata.GithubRepo, testdata.GithubRepo, modelPull, testdata.User)

	projectCommandBuilder.VerifyWasCalledOnce().BuildAutoplanCommands(Any[*command.Context]())
}

// A window for one project is checked when that project runs, so other
// projects in the same pull request still plan and apply.
func TestDefaultProjectCommandRunner_MaintenanceForOneProject(t *testing.T) {
	f := newStopFixture(t)
	f.runner.Maintenance = startMaintenance(t, locking.MaintenanceWindow{
		Host: "github.com", RepoName: "runatlantis/atlantis", Dir: "network", Workspace: "default", Plans: true, Reason: "state migration", By: "Ada Admin",
	})
	f.ctx.Pull = models.PullRequest{BaseRepo: testdata.GithubRepo, Num: 1}
	f.ctx.RepoRelDir = "network"

	res := f.runner.Plan(f.ctx)
	ErrContains(t, "atlantis plan is blocked by a maintenance window on runatlantis/atlantis.\nScope: directory network, workspace default\nReason: state migration", res.Error)
	Assert(t, res.PlanSuccess == nil, "a frozen plan must not run")
	f.init.VerifyWasCalled(Never()).Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())

	ErrContains(t, "atlantis apply is blocked", f.runner.Apply(f.ctx).Error)
	ErrContains(t, "atlantis import is blocked", f.runner.Import(f.ctx).Error)
	ErrContains(t, "atlantis state rm is blocked", f.runner.StateRm(f.ctx).Error)
	Equals(t, 0, f.unlocked)

	// Another project in the same pull request runs.
	f.ctx.RepoRelDir = "edge"
	Ok(t, os.Mkdir(filepath.Join(f.repoDir, "edge"), 0o700))
	f.ctx.Steps = []valid.Step{{StepName: "init"}}
	When(f.init.Run(Any[command.ProjectContext](), Any[[]string](), Any[string](), Any[map[string]string]())).ThenReturn("init", nil)
	res = f.runner.Plan(f.ctx)
	Ok(t, res.Error)
	Assert(t, res.PlanSuccess != nil, "other projects plan")
}
