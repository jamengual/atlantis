// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

var testPolicySets = &valid.PolicySets{
	Owners: valid.PolicyOwners{Users: []string{"root"}},
	PolicySets: []valid.PolicySet{
		{Name: "security", ApproveCount: 2, Owners: valid.PolicyOwners{Users: []string{"carol", "dave"}, Teams: []string{"sec"}}, PreventSelfApprove: true},
		{Name: "tagging", ApproveCount: 1},
	},
}

var policyResults = []models.PolicySetResult{
	{
		PolicySetName: "security", Passed: false, ReqApprovalCount: 2, Hashes: []string{"h1"},
		PolicyOutput: "FAIL - main.tf - <script>alert(1)</script> bucket is public\n1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions",
		Approvals:    []models.PolicySetApproval{{Approver: "carol", Hashes: []string{"h1"}}, {Approver: "dave", Hashes: []string{"h0"}}},
	},
	{PolicySetName: "tagging", Passed: true, ReqApprovalCount: 1, PolicyOutput: "1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions"},
	{PolicySetName: "retired", Passed: false, ReqApprovalCount: 1, PolicyOutput: "FAIL - old rule"},
}

// policyCheck records a policy check for the project, as Atlantis does after
// a plan.
func (f *fixture) policyCheck(t *testing.T, p models.PullRequest, dir string) {
	t.Helper()
	_, err := f.db.UpdatePullWithResults(p, []command.ProjectResult{{
		Command: command.PolicyCheck, RepoRelDir: dir, Workspace: "default",
		ProjectCommandOutput: command.ProjectCommandOutput{
			PolicyCheckResults: &models.PolicyCheckResults{PolicySetResults: policyResults},
			Failure:            "policy set: security: conftest: some policies failed",
		},
	}})
	Ok(t, err)
}

func TestLegacyStore_PoliciesFromPullStatus(t *testing.T) {
	f := newFixture(t)
	f.store.PolicySets = testPolicySets
	f.plan(t, pull(7), "network", true)
	f.policyCheck(t, pull(7), "network")

	pulls, err := f.store.ListPulls(context.Background())
	Ok(t, err)
	proj := pulls[0].Projects[0]
	Equals(t, webui.StatePolicyFailed, proj.State)
	Equals(t, 3, len(proj.Policies))

	sec := proj.Policies[0]
	Equals(t, "security", sec.Name)
	Assert(t, sec.Configured && !sec.Passed, "security is configured and failed")
	Equals(t, 2, sec.Required)
	Equals(t, []webui.PolicyApproval{{By: "carol", Current: true}, {By: "dave", Current: false}}, sec.Approvals)
	Equals(t, 1, sec.CurrentApprovals())
	Equals(t, webui.PolicyOwners{Users: []string{"carol", "dave"}, Teams: []string{"sec"}}, sec.Owners)
	Assert(t, sec.PreventSelfApprove, "prevent self approve comes from the config")
	Assert(t, !sec.Cleared(), "one current approval of two doesn't clear the set")
	Equals(t, "", sec.Output)

	Assert(t, proj.Policies[1].Cleared(), "passed set is cleared")
	// A set that is no longer configured can't be cleared by approvals.
	Assert(t, !proj.Policies[2].Configured && !proj.Policies[2].Cleared(), "retired set stays failing")
	Equals(t, []string{"security", "retired"}, proj.FailingPolicySets())
	Assert(t, pulls[0].PolicyFailing(), "the pull request has failing policies")

	// Without a clone on this replica, there is no output to show.
	pp, err := f.store.GetPolicies(context.Background(), webui.Repository{FullName: "acme/infra"}, 7, networkRef)
	Ok(t, err)
	Equals(t, webui.PolicyOutputMissing, pp.Output)
	Equals(t, webui.PolicyOwners{Users: []string{"root"}}, pp.Admins)

	missing, err := f.store.GetPolicies(context.Background(), webui.Repository{FullName: "acme/infra"}, 7, webui.ProjectRef{Dir: "nope", Workspace: "default"})
	Ok(t, err)
	Assert(t, missing == nil, "unknown project returns nil")
}

func TestLegacyStore_PoliciesWithoutConfig(t *testing.T) {
	f := newFixture(t)
	f.plan(t, pull(7), "network", true)
	f.policyCheck(t, pull(7), "network")
	pulls, err := f.store.ListPulls(context.Background())
	Ok(t, err)
	for _, s := range pulls[0].Projects[0].Policies {
		Assert(t, !s.Configured, "without the policy config, %s is unconfigured", s.Name)
	}
}

func TestLegacyStore_PolicyOutputFromTheClone(t *testing.T) {
	results, err := json.Marshal(policyResults)
	Ok(t, err)
	cases := []struct {
		name  string
		setup func(t *testing.T, f *planFixture)
		want  webui.PolicyOutputStatus
	}{
		{"ready", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			f.write(t, "default-policyout.json", results, 0)
		}, webui.PolicyOutputReady},
		{"older than the plan", func(t *testing.T, f *planFixture) {
			f.write(t, "default-policyout.json", results, time.Hour)
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
		}, webui.PolicyOutputOutdated},
		{"no plan file", func(t *testing.T, f *planFixture) {
			f.write(t, "default-policyout.json", results, 0)
		}, webui.PolicyOutputMissing},
		{"no output file", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
		}, webui.PolicyOutputMissing},
		{"not JSON", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			f.write(t, "default-policyout.json", []byte("{not json"), 0)
		}, webui.PolicyOutputUnreadable},
		{"symlink out of the clone", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			outside := t.TempDir() + "/secret.json"
			Ok(t, os.WriteFile(outside, results, 0o600))
			Ok(t, os.Symlink(outside, f.projDir+"/default-policyout.json"))
		}, webui.PolicyOutputUnreadable},
		{"no clone", func(t *testing.T, f *planFixture) { Ok(t, os.RemoveAll(f.dataDir)) }, webui.PolicyOutputMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPlanFixture(t)
			f.store.PolicySets = testPolicySets
			f.policyCheck(t, pull(7), "network")
			c.setup(t, f)
			pp, err := f.store.GetPolicies(context.Background(), webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, 7, networkRef)
			Ok(t, err)
			Equals(t, c.want, pp.Output)
			if c.want == webui.PolicyOutputReady {
				Assert(t, strings.Contains(pp.Sets[0].Output, "bucket is public"), "security output: %q", pp.Sets[0].Output)
				Assert(t, strings.Contains(pp.Sets[1].Output, "1 passed"), "tagging output: %q", pp.Sets[1].Output)
				Assert(t, !pp.CheckedAt.IsZero(), "checked time comes from the file")
				// Approvals come from the pull status, not the file.
				Equals(t, 1, pp.Sets[0].CurrentApprovals())
			} else {
				for _, s := range pp.Sets {
					Equals(t, "", s.Output)
				}
			}
		})
	}
}

type recordedComment struct {
	repo    models.Repo
	num     int
	comment string
	command string
}

type fakeCommenter struct {
	comments []recordedComment
	err      error
}

func (c *fakeCommenter) CreateComment(_ logging.SimpleLogging, repo models.Repo, num int, comment string, cmd string) error {
	c.comments = append(c.comments, recordedComment{repo, num, comment, cmd})
	return c.err
}

type recordedRun struct {
	repo models.Repo
	user models.User
	num  int
	cmd  *events.CommentCommand
}

type fakeCommandRunner struct{ runs []recordedRun }

func (r *fakeCommandRunner) RunCommentCommand(baseRepo models.Repo, headRepo *models.Repo, p *models.PullRequest, user models.User, num int, cmd *events.CommentCommand) {
	r.runs = append(r.runs, recordedRun{baseRepo, user, num, cmd})
}

func TestLegacyActions_ApprovePoliciesRunsTheCommentCommand(t *testing.T) {
	f := newFixture(t)
	f.plan(t, pull(7), "network", true)
	commenter, runner := &fakeCommenter{}, &fakeCommandRunner{}
	actions := &webui.LegacyActions{PullStatuses: f.db, Commenter: commenter, Commands: runner, Logger: logging.NewNoopLogger(t), Start: func(fn func()) { fn() }}
	repo := webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}

	cases := []struct {
		name    string
		req     webui.PolicyApprovalRequest
		want    events.CommentCommand
		comment string
	}{
		{"every project", webui.PolicyApprovalRequest{Repo: repo, Num: 7, Login: "carol"},
			events.CommentCommand{Name: command.ApprovePolicies}, "atlantis approve_policies\n"},
		{"one dir", webui.PolicyApprovalRequest{Repo: repo, Num: 7, Login: "carol", Project: &webui.ProjectRef{Dir: "network", Workspace: "default"}},
			events.CommentCommand{Name: command.ApprovePolicies, RepoRelDir: "network", Workspace: "default"}, "atlantis approve_policies -d network -w default\n"},
		{"one named project and set", webui.PolicyApprovalRequest{Repo: repo, Num: 7, Login: "carol", Project: &webui.ProjectRef{Dir: "network", Workspace: "default", Name: "net"}, PolicySet: "security"},
			events.CommentCommand{Name: command.ApprovePolicies, ProjectName: "net", PolicySet: "security"}, "atlantis approve_policies -p net --policy-set security\n"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Ok(t, actions.ApprovePolicies(c.req))
			Equals(t, i+1, len(runner.runs))
			run := runner.runs[i]
			Equals(t, testRepo, run.repo)
			Equals(t, 7, run.num)
			// The approval is recorded for the GitHub login, as if they had commented.
			Equals(t, models.User{Username: "carol"}, run.user)
			Equals(t, c.want, *run.cmd)
			cm := commenter.comments[i]
			Equals(t, 7, cm.num)
			Equals(t, "approve_policies", cm.command)
			Assert(t, strings.HasPrefix(cm.comment, "@carol approved failing policies from the Atlantis web UI."), "comment: %q", cm.comment)
			Assert(t, strings.Contains(cm.comment, c.comment), "comment %q should contain %q", cm.comment, c.comment)
		})
	}
}

func TestLegacyActions_ApprovePoliciesRefuses(t *testing.T) {
	f := newFixture(t)
	f.plan(t, pull(7), "network", true)
	gitlab := pull(8)
	gitlab.BaseRepo.VCSHost = models.VCSHost{Hostname: "gitlab.com", Type: models.Gitlab}
	f.plan(t, gitlab, "network", true)
	commenter, runner := &fakeCommenter{}, &fakeCommandRunner{}
	actions := &webui.LegacyActions{PullStatuses: f.db, Commenter: commenter, Commands: runner, Logger: logging.NewNoopLogger(t), Start: func(fn func()) { fn() }}
	gh := webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}

	err := actions.ApprovePolicies(webui.PolicyApprovalRequest{Repo: webui.Repository{VCSHost: "gitlab.com", FullName: "acme/infra"}, Num: 8, Login: "carol"})
	Assert(t, errors.Is(err, webui.ErrPolicyApprovalNotGitHub), "gitlab: %v", err)
	err = actions.ApprovePolicies(webui.PolicyApprovalRequest{Repo: gh, Num: 99, Login: "carol"})
	Assert(t, errors.Is(err, webui.ErrPullNotTracked), "unknown pull: %v", err)
	// A login that isn't a GitHub username can't inject markdown into the comment.
	err = actions.ApprovePolicies(webui.PolicyApprovalRequest{Repo: gh, Num: 7, Login: "carol](https://evil.example)"})
	ErrContains(t, "is not a GitHub login", err)
	err = (&webui.LegacyActions{}).ApprovePolicies(webui.PolicyApprovalRequest{Repo: gh, Num: 7, Login: "carol"})
	Assert(t, errors.Is(err, webui.ErrPolicyApprovalUnavailable), "unwired: %v", err)
	Equals(t, 0, len(runner.runs))
	Equals(t, 0, len(commenter.comments))

	// When the comment fails, the command doesn't run.
	commenter.err = errors.New("vcs down")
	err = actions.ApprovePolicies(webui.PolicyApprovalRequest{Repo: gh, Num: 7, Login: "carol"})
	ErrContains(t, "commenting on the pull request: vcs down", err)
	Equals(t, 0, len(runner.runs))
}
