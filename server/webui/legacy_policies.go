// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/core/runtime"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/utils"
)

// MaxPolicyOutputBytes is the largest policy check output file the UI reads.
const MaxPolicyOutputBytes = 8 << 20

// policySets turns a project's stored policy status into policy sets,
// adding the required approvals and owners from the server-side config.
func (s *LegacyStore) policySets(status []models.PolicySetStatus) []PolicySet {
	if len(status) == 0 {
		return nil
	}
	out := make([]PolicySet, 0, len(status))
	for _, st := range status {
		set := PolicySet{Name: st.PolicySetName, Passed: st.Passed}
		for _, a := range st.Approvals {
			set.Approvals = append(set.Approvals, PolicyApproval{
				By:      a.Approver,
				Current: models.ApprovalCoversAllHashes(a.Hashes, st.Hashes),
			})
		}
		if s.PolicySets != nil {
			for _, cfg := range s.PolicySets.PolicySets {
				if cfg.Name != st.PolicySetName {
					continue
				}
				set.Configured = true
				set.Required = cfg.ApproveCount
				set.Owners = toPolicyOwners(cfg.Owners)
				set.PreventSelfApprove = cfg.PreventSelfApprove
			}
		}
		out = append(out, set)
	}
	return out
}

func toPolicyOwners(o valid.PolicyOwners) PolicyOwners {
	return PolicyOwners{Users: slices.Clone(o.Users), Teams: slices.Clone(o.Teams)}
}

func (s *LegacyStore) GetPolicies(_ context.Context, repo Repository, num int, ref ProjectRef) (*ProjectPolicies, error) {
	st, ps, err := s.findProject(repo, num, ref)
	if err != nil || st == nil {
		return nil, err
	}
	out := &ProjectPolicies{Sets: s.policySets(ps.PolicyStatus), Output: PolicyOutputMissing}
	if s.PolicySets != nil {
		out.Admins = toPolicyOwners(s.PolicySets.Owners)
	}
	if len(out.Sets) == 0 {
		return out, nil
	}
	path, info, status, err := s.locatePolicyOutput(*st, *ps)
	if err != nil {
		return nil, err
	}
	out.Output = status
	if info != nil {
		out.CheckedAt = info.ModTime()
	}
	if status != PolicyOutputReady {
		return out, nil
	}
	results, ok := readPolicyOutput(path, info)
	if !ok {
		out.Output = PolicyOutputUnreadable
		return out, nil
	}
	for i := range out.Sets {
		for _, r := range results {
			if r.PolicySetName == out.Sets[i].Name {
				out.Sets[i].Output = r.PolicyOutput
			}
		}
	}
	return out, nil
}

// locatePolicyOutput finds the file the policy check step writes next to the
// project. Like the plan JSON, it is only trusted when it is a regular file
// inside the clone, written no earlier than the current saved plan.
func (s *LegacyStore) locatePolicyOutput(st models.PullStatus, ps models.ProjectStatus) (string, fs.FileInfo, PolicyOutputStatus, error) {
	if s.WorkingDir == nil {
		return "", nil, PolicyOutputMissing, nil
	}
	wd, err := s.WorkingDir.GetWorkingDir(st.Pull.BaseRepo, st.Pull, ps.Workspace)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, PolicyOutputMissing, nil
	}
	if err != nil {
		return "", nil, "", err
	}
	projDir := filepath.Join(wd, ps.RepoRelDir)
	if utils.EnsureSubPath(wd, projDir) != nil {
		return "", nil, PolicyOutputUnreadable, nil
	}
	pctx := command.ProjectContext{
		BaseRepo:          st.Pull.BaseRepo,
		Pull:              st.Pull,
		RepoRelDir:        ps.RepoRelDir,
		Workspace:         ps.Workspace,
		ProjectName:       ps.ProjectName,
		LocalSharePlanDir: s.SharePlanDir,
	}
	planInfo, err := os.Lstat(runtime.GetPlanFilePath(pctx, projDir))
	if err != nil || !planInfo.Mode().IsRegular() {
		return "", nil, PolicyOutputMissing, nil
	}
	path := filepath.Join(projDir, pctx.GetPolicyCheckResultFileName())
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, PolicyOutputMissing, nil
	}
	if err != nil || !info.Mode().IsRegular() || utils.EnsureSubPathResolved(wd, path) != nil || info.Size() > MaxPolicyOutputBytes {
		return "", nil, PolicyOutputUnreadable, nil
	}
	if info.ModTime().Before(planInfo.ModTime()) {
		return "", info, PolicyOutputOutdated, nil
	}
	return path, info, PolicyOutputReady, nil
}

// readPolicyOutput reads the policy check results, checking the file is
// still the one locatePolicyOutput saw.
func readPolicyOutput(path string, want fs.FileInfo) ([]models.PolicySetResult, bool) {
	// #nosec G304 -- path is inside the clone directory and was checked by locatePolicyOutput.
	fh, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil || !os.SameFile(info, want) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(fh, MaxPolicyOutputBytes+1))
	if err != nil || len(b) > MaxPolicyOutputBytes {
		return nil, false
	}
	var results []models.PolicySetResult
	if err := json.Unmarshal(b, &results); err != nil {
		return nil, false
	}
	return results, true
}

// CommentCommandRunner runs a command as if it came from a pull request
// comment. *events.DefaultCommandRunner implements it.
type CommentCommandRunner interface {
	RunCommentCommand(baseRepo models.Repo, maybeHeadRepo *models.Repo, maybePull *models.PullRequest, user models.User, pullNum int, cmd *events.CommentCommand)
}

// PullCommenter comments on pull requests. vcs.Client implements it.
type PullCommenter interface {
	CreateComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, comment string, command string) error
}

// ErrPolicyApprovalUnavailable is returned when this replica can't run
// policy approvals.
var ErrPolicyApprovalUnavailable = errors.New("this replica can't run policy approvals")

// ErrPolicyApprovalNotGitHub is returned for pull requests outside GitHub,
// because web sign-in only maps people to GitHub logins.
var ErrPolicyApprovalNotGitHub = errors.New("approving policies from the web UI works only for GitHub repositories")

// ErrPullNotTracked is returned when Atlantis has no status for the pull
// request.
var ErrPullNotTracked = errors.New("atlantis has no status for this pull request")

func (a *LegacyActions) ApprovePolicies(req PolicyApprovalRequest) error {
	if a.Commands == nil || a.Commenter == nil || a.PullStatuses == nil || a.Logger == nil {
		return ErrPolicyApprovalUnavailable
	}
	if !githubLogin.MatchString(req.Login) {
		return fmt.Errorf("%q is not a GitHub login", req.Login)
	}
	statuses, err := a.PullStatuses.ListPullStatuses()
	if err != nil {
		return fmt.Errorf("reading pull status: %w", err)
	}
	var pull *models.PullRequest
	for i := range statuses {
		p := statuses[i].Pull
		if p.BaseRepo.FullName == req.Repo.FullName && p.Num == req.Num && sameHost(req.Repo.VCSHost, p.BaseRepo.VCSHost.Hostname) {
			pull = &statuses[i].Pull
		}
	}
	if pull == nil {
		return ErrPullNotTracked
	}
	if pull.BaseRepo.VCSHost.Type != models.Github {
		return ErrPolicyApprovalNotGitHub
	}
	cmd := &events.CommentCommand{Name: command.ApprovePolicies, PolicySet: req.PolicySet}
	if req.Project != nil {
		if req.Project.Name != "" {
			cmd.ProjectName = req.Project.Name
		} else {
			cmd.RepoRelDir = req.Project.Dir
			cmd.Workspace = req.Project.Workspace
		}
	}
	if err := a.Commenter.CreateComment(a.Logger, pull.BaseRepo, pull.Num, approvalComment(req, cmd), command.ApprovePolicies.String()); err != nil {
		return fmt.Errorf("commenting on the pull request: %w", err)
	}
	baseRepo := pull.BaseRepo
	user := models.User{Username: req.Login}
	num := pull.Num
	a.start(func() {
		// Like a comment webhook, let the runner fetch the pull request and
		// head repo from the VCS so it acts on their current state.
		a.Commands.RunCommentCommand(baseRepo, nil, nil, user, num, cmd)
	})
	return nil
}

func (a *LegacyActions) start(f func()) {
	if a.Start != nil {
		a.Start(f)
		return
	}
	go f()
}

// githubLogin matches GitHub usernames, so a login can't add markdown to
// the pull request comment.
var githubLogin = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// approvalComment says who approved from the web UI and what, in the form of
// the equivalent comment command.
func approvalComment(req PolicyApprovalRequest, cmd *events.CommentCommand) string {
	args := []string{"atlantis", "approve_policies"}
	switch {
	case cmd.ProjectName != "":
		args = append(args, "-p", cmd.ProjectName)
	case cmd.RepoRelDir != "":
		args = append(args, "-d", cmd.RepoRelDir, "-w", cmd.Workspace)
	}
	if cmd.PolicySet != "" {
		args = append(args, "--policy-set", cmd.PolicySet)
	}
	return fmt.Sprintf("@%s approved failing policies from the Atlantis web UI. Atlantis is running:\n\n```\n%s\n```",
		req.Login, strings.Join(args, " "))
}
